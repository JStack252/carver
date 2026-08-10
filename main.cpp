//Carver
//recovers deleted files from a disk image and then checks them for hidden stuff
//uses sleuthkit for the filesystem parsing, scalpel's carving approach,
//libmagic to identify content and yara for the rules
//runs in 5 phases, each one feeds the next

#include <tsk/libtsk.h>
#include <magic.h>
#include <yara.h>
#include <dirent.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <string>
#include <vector>
#include <algorithm>

//a chunk of the disk, used for both free space runs and file extents
struct ByteRange {
    TSK_OFF_T start;
    TSK_OFF_T length;
};

//one carving signature, same fields scalpel.conf uses
struct Signature {
    std::string ext;
    bool case_sensitive;
    size_t max_size;
    std::vector<unsigned char> header;
    std::vector<unsigned char> footer;
};

//biggest file we will hold in memory to scan, anything past this gets streamed
static const size_t SCAN_CAP = 64u * 1024u * 1024u;

//turns a scalpel style signature string into actual bytes
//handles \xNN escapes and plain characters mixed together
static std::vector<unsigned char> parse_sig_string(const std::string &s) {
    std::vector<unsigned char> out;
    for (size_t i = 0; i < s.size(); ) {
        if (s[i] == '\\' && i + 3 < s.size() && (s[i+1] == 'x' || s[i+1] == 'X')) {
            char hex[3] = { s[i+2], s[i+3], 0 };
            out.push_back((unsigned char)strtol(hex, NULL, 16));
            i += 4;
        } else {
            out.push_back((unsigned char)s[i]);
            i += 1;
        }
    }
    return out;
}

//built in signatures so the program works without a config file
//jpg max is set to 50mb on purpose, the dfrws test image has a 24.5mb jpeg in it
//to catch tools that assume a small default and truncate it
static void load_default_signatures(std::vector<Signature> &sigs) {
    struct { const char *ext; bool cs; size_t max; const char *hdr; const char *ftr; } defs[] = {
        { "jpg", true, 50000000, "\\xff\\xd8\\xff\\xe0", "\\xff\\xd9" },
        { "jpg", true, 50000000, "\\xff\\xd8\\xff\\xe1", "\\xff\\xd9" },
        { "gif", true,  5000000, "GIF87a",                "\\x00\\x3b" },
        { "gif", true,  5000000, "GIF89a",                "\\x00\\x3b" },
        { "png", true, 20000000, "\\x89PNG\\x0d\\x0a",    "IEND\\xae\\x42\\x60\\x82" },
        { "pdf", true, 50000000, "%PDF",                  "%%EOF" },
        { "zip", true, 50000000, "PK\\x03\\x04",          "PK\\x05\\x06" },
        { "htm", false, 1000000, "<html",                 "</html>" },
        { "doc", true, 10000000, "\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1", "" },
    };
    for (size_t i = 0; i < sizeof(defs)/sizeof(defs[0]); i++) {
        Signature sig;
        sig.ext = defs[i].ext;
        sig.case_sensitive = defs[i].cs;
        sig.max_size = defs[i].max;
        sig.header = parse_sig_string(defs[i].hdr);
        //empty footer string means this format has no footer
        if (defs[i].ftr[0] != '\0') sig.footer = parse_sig_string(defs[i].ftr);
        sigs.push_back(sig);
    }
}

//loads a real scalpel.conf if one is passed in
//format is: extension  case_sensitive  max_size  header  [footer]
//lines starting with # are comments and get skipped
static bool load_conf(const char *path, std::vector<Signature> &sigs) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        char ext[64], cs[8], hdr[256], ftr[256];
        unsigned long long maxsz = 0;
        //footer is optional so n can come back as 4 or 5
        int n = sscanf(line, "%63s %7s %llu %255s %255s", ext, cs, &maxsz, hdr, ftr);
        if (n < 4) continue;
        Signature sig;
        sig.ext = ext;
        sig.case_sensitive = (cs[0] == 'y' || cs[0] == 'Y');
        sig.max_size = (size_t)maxsz;
        sig.header = parse_sig_string(hdr);
        if (n >= 5) sig.footer = parse_sig_string(ftr);
        sigs.push_back(sig);
    }
    fclose(f);
    return true;
}

//compares bytes against a signature pattern
//lowercases both sides if the signature is not case sensitive
static bool sig_match(const unsigned char *data, size_t avail,
                      const std::vector<unsigned char> &pat, bool case_sensitive) {
    if (pat.empty() || avail < pat.size()) return false;
    for (size_t i = 0; i < pat.size(); i++) {
        unsigned char a = data[i], b = pat[i];
        if (!case_sensitive) { a = tolower(a); b = tolower(b); }
        if (a != b) return false;
    }
    return true;
}

//figures out the real length of a jpeg by walking its structure
//searching for the first ffd9 does not work because those two bytes come up
//all the time inside the compressed image data, so you end up truncating the file
//instead this walks marker to marker the way a decoder would
//every marker is ff followed by a marker byte, most carry a 2 byte big endian length
//rst markers and tem have no length so they get skipped
//after the sos marker the entropy data runs until the next real marker, where
//ff00 is a stuffed byte and ffd0-ffd7 are restarts, neither of which end it
//returns 0 if the structure does not parse, which is itself useful information
//because it usually means the file is fragmented
static size_t jpeg_true_length(const unsigned char *d, size_t n) {
    if (n < 4 || d[0] != 0xFF || d[1] != 0xD8) return 0;

    size_t i = 2;
    while (i + 1 < n) {
        //if we are not sitting on a marker then we lost sync somewhere
        if (d[i] != 0xFF) return 0;
        //skip any fill bytes
        while (i < n && d[i] == 0xFF) i++;
        if (i >= n) return 0;

        unsigned char marker = d[i];
        i++;

        //end of image, this is the real end of the file
        if (marker == 0xD9) return i;
        //these markers carry no length so just move on
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) continue;

        if (i + 1 >= n) return 0;
        size_t seglen = ((size_t)d[i] << 8) | (size_t)d[i+1];
        //length includes its own 2 bytes so anything under 2 is broken
        if (seglen < 2 || i + seglen > n) return 0;

        //start of scan, after this comes the actual compressed data
        if (marker == 0xDA) {
            i += seglen;
            while (i + 1 < n) {
                if (d[i] == 0xFF) {
                    unsigned char m2 = d[i+1];
                    //stuffed byte, not a marker
                    if (m2 == 0x00) { i += 2; continue; }
                    //restart marker, also not the end
                    if (m2 >= 0xD0 && m2 <= 0xD7) { i += 2; continue; }
                    //anything else is a real marker so stop scanning
                    break;
                }
                i++;
            }
            continue;
        }
        i += seglen;
    }
    return 0;
}

//jpegs show up under a few different extensions
static bool is_jpeg_ext(const std::string &e) {
    return e == "jpg" || e == "jpeg" || e == "jfif";
}

//what libmagic should say for a correctly carved file of each type
//if none of these show up in the description then the carve is probably garbage
static std::vector<std::string> expected_for(const std::string &ext) {
    std::vector<std::string> v;
    if (is_jpeg_ext(ext))              { v.push_back("JPEG"); }
    else if (ext == "png")             { v.push_back("PNG"); }
    else if (ext == "gif")             { v.push_back("GIF"); }
    else if (ext == "pdf")             { v.push_back("PDF"); }
    else if (ext == "zip")             { v.push_back("Zip"); v.push_back("Microsoft"); }
    else if (ext == "htm" || ext == "html") { v.push_back("HTML"); v.push_back("text"); }
    else if (ext == "doc" || ext == "xls" || ext == "ppt") {
        v.push_back("Composite Document"); v.push_back("Microsoft");
    }
    else if (ext == "bmp")             { v.push_back("bitmap"); }
    else if (ext == "gz")              { v.push_back("gzip"); }
    else if (ext == "mp3")             { v.push_back("Audio"); v.push_back("MPEG"); }
    return v;
}

//case insensitive substring check, copies both strings and lowercases them
static bool contains_ci(const std::string &hay, const std::string &needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    std::string h = hay, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

//libmagic prints these when it recognizes the container but cannot read inside it
//that means the file is cut off or has something wrong in the middle
static bool looks_truncated(const std::string &desc) {
    static const char *warn[] = {
        "can't read", "cannot read", "truncated", "corrupt",
        "error", "bad", "invalid"
    };
    for (size_t i = 0; i < sizeof(warn)/sizeof(warn[0]); i++) {
        if (contains_ci(desc, warn[i])) return true;
    }
    return false;
}

enum Verdict { V_VALID, V_PARTIAL, V_FRAGMENTED, V_MISMATCH, V_UNKNOWN };

static const char *verdict_name(Verdict v) {
    switch (v) {
        case V_VALID:      return "VALID";
        case V_PARTIAL:    return "PARTIAL";
        case V_FRAGMENTED: return "FRAGMENTED";
        case V_MISMATCH:   return "MISMATCH";
        default:           return "UNKNOWN";
    }
}

//compares what libmagic says against what the signature claimed
static Verdict classify(const std::string &ext, const std::string &desc) {
    std::vector<std::string> want = expected_for(ext);
    //no rule written for this format yet
    if (want.empty()) return V_UNKNOWN;
    bool type_ok = false;
    for (size_t i = 0; i < want.size(); i++) {
        if (contains_ci(desc, want[i])) { type_ok = true; break; }
    }
    //content is not the type we said it was, so the header matched by luck
    if (!type_ok) return V_MISMATCH;
    if (looks_truncated(desc)) return V_PARTIAL;
    return V_VALID;
}

//one thing found inside a file during phase 5
struct Finding {
    std::string severity;
    std::string label;
    long long offset;
};

//everything found in one file, plus where the file came from
struct FileReport {
    std::string source;
    std::string name;
    std::string detected;
    long long size;
    std::vector<Finding> findings;
};

//container formats are supposed to have other files inside them
static bool type_is_container(const std::string &det) {
    return contains_ci(det, "Zip") || contains_ci(det, "Composite Document") ||
           contains_ci(det, "PDF") || contains_ci(det, "Microsoft") ||
           contains_ci(det, "tar") || contains_ci(det, "gzip");
}

//flat image formats are not, so anything foreign inside one is a problem
static bool type_is_flat_image(const std::string &det) {
    return contains_ci(det, "JPEG") || contains_ci(det, "PNG") ||
           contains_ci(det, "GIF")  || contains_ci(det, "bitmap");
}

static bool type_is_text(const std::string &det) {
    return contains_ci(det, "text") || contains_ci(det, "HTML") ||
           contains_ci(det, "XML")  || contains_ci(det, "script");
}

struct Indicator {
    const char *label;
    const char *pat;
    size_t len;
    bool binary_ok;
};

//hardcoded strings worth looking for
//kept around so the program still reports something if no yara rules are installed
static const Indicator INDICATORS[] = {
    { "Windows PE executable stub", "This program cannot be run in DOS mode", 38, true },
    { "ELF executable header",      "\x7f" "ELF", 4, true },
    { "Script shebang",             "#!/bin/", 7, false },
    { "PDF JavaScript",             "/JavaScript", 11, true },
    { "PDF OpenAction",             "/OpenAction", 11, true },
    { "PDF Launch action",          "/Launch", 7, true },
    { "PDF embedded file",          "/EmbeddedFile", 13, true },
    { "Office VBA project",         "_VBA_PROJECT", 12, true },
    { "OOXML macro stream",         "vbaProject.bin", 14, true },
    { "HTML script tag",            "<script", 7, false },
    { "PHP code block",             "<?php", 5, false },
    { "Base64 decode call",         "FromBase64String", 16, false },
    { "PowerShell encoded command", "-EncodedCommand", 15, false },
    { "WScript shell object",       "WScript.Shell", 13, false },
    { "eval() call",                "eval(", 5, false },
};

//finds a pattern in a buffer and gives back where it was
static bool mem_find(const unsigned char *d, size_t n,
                     const char *pat, size_t plen, size_t *where) {
    if (plen == 0 || n < plen) return false;
    for (size_t i = 0; i + plen <= n; i++) {
        if (memcmp(d + i, pat, plen) == 0) { *where = i; return true; }
    }
    return false;
}

//compiled yara rules, stays loaded for the whole run
static YR_RULES *g_yara = NULL;

//lets the yara callback get at the findings list for the file being scanned
struct YaraCtx { std::vector<Finding> *out; };

//called by yara every time a rule matches
//this is the yara 4.x signature, on 3.x there is no scan context parameter
static int yara_cb(YR_SCAN_CONTEXT *context, int message,
                   void *message_data, void *user_data) {
    (void)context;
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    YR_RULE *rule = (YR_RULE *)message_data;
    YaraCtx *y = (YaraCtx *)user_data;

    //rules carry their own severity and description in the meta block
    //so adding a new rule does not mean changing anything in here
    const char *sev = "SUSPICIOUS";
    const char *desc = NULL;
    YR_META *meta;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type != META_TYPE_STRING) continue;
        if (strcmp(meta->identifier, "severity") == 0)    sev = meta->string;
        if (strcmp(meta->identifier, "description") == 0) desc = meta->string;
    }

    Finding f;
    f.severity = sev;
    f.offset = 0;
    f.label = std::string("YARA:") + rule->identifier;
    if (desc) f.label += std::string(" - ") + desc;
    y->out->push_back(f);

    return CALLBACK_CONTINUE;
}

//compiles every .yar file in the rules directory into one rule set
//returns null if the directory is missing or nothing compiled
static YR_RULES *load_yara_rules(const char *dir, int *rule_count) {
    *rule_count = 0;

    YR_COMPILER *comp = NULL;
    if (yr_compiler_create(&comp) != ERROR_SUCCESS) return NULL;

    DIR *d = opendir(dir);
    int files_added = 0;
    if (d != NULL) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            //only take files ending in .yar
            size_t l = strlen(e->d_name);
            if (l < 5 || strcmp(e->d_name + l - 4, ".yar") != 0) continue;

            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            FILE *f = fopen(path, "r");
            if (f == NULL) continue;

            //add_file gives back how many errors it hit, 0 means it compiled
            int errs = yr_compiler_add_file(comp, f, NULL, path);
            fclose(f);
            if (errs == 0) files_added++;
            else fprintf(stderr, "  YARA: %d error(s) compiling %s\n", errs, path);
        }
        closedir(d);
    }

    if (files_added == 0) { yr_compiler_destroy(comp); return NULL; }

    YR_RULES *rules = NULL;
    if (yr_compiler_get_rules(comp, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(comp);
        return NULL;
    }
    yr_compiler_destroy(comp);

    //count them so we can print how many loaded
    YR_RULE *r;
    yr_rules_foreach(rules, r) { (*rule_count)++; }
    return rules;
}

//phase 5, checks one file for anything hidden in it
//looks for other formats embedded in it, data stuck on the end,
//known bad strings, and whatever the yara rules catch
static std::vector<Finding>
scan_content(const unsigned char *d, size_t n,
             const std::string &detected,
             const std::vector<Signature> &sigs) {
    std::vector<Finding> out;
    if (n == 0) return out;

    bool container = type_is_container(detected);
    bool flat_img  = type_is_flat_image(detected);
    bool textual   = type_is_text(detected);

    //look for other file formats inside this one
    //start at 1 because offset 0 is just this file's own header
    //only report each format once so a big archive does not spam the output
    std::vector<std::string> seen;
    for (size_t i = 1; i < n; i++) {
        for (size_t s = 0; s < sigs.size(); s++) {
            if (!sig_match(d + i, n - i, sigs[s].header, sigs[s].case_sensitive)) continue;
            if (std::find(seen.begin(), seen.end(), sigs[s].ext) != seen.end()) continue;
            seen.push_back(sigs[s].ext);

            //a format inside itself is normal, jpegs carry a thumbnail jpeg in
            //the exif data and archives hold other archives, so do not flag those
            bool same_as_host = false;
            std::vector<std::string> want = expected_for(sigs[s].ext);
            for (size_t w = 0; w < want.size(); w++) {
                if (contains_ci(detected, want[w])) { same_as_host = true; break; }
            }

            Finding f;
            f.offset = (long long)i;
            f.label = "embedded " + sigs[s].ext + " signature";
            if (same_as_host)   f.severity = "INFO";
            else if (container) f.severity = "INFO";
            else if (flat_img)  f.severity = "HIGH";
            else                f.severity = "SUSPICIOUS";
            out.push_back(f);
        }
    }

    //for jpegs we already know where the file really ends
    //so anything after that got stuck on there on purpose and an image viewer
    //will never show it, which is how polyglots and stego carriers get built
    if (contains_ci(detected, "JPEG")) {
        size_t truelen = jpeg_true_length(d, n);
        if (truelen > 0 && truelen < n) {
            size_t extra = n - truelen;
            //ignore a few bytes of padding
            if (extra > 16) {
                Finding f;
                f.severity = "HIGH";
                f.offset = (long long)truelen;
                char b[160];
                snprintf(b, sizeof(b),
                         "%zu bytes appended after JPEG end-of-image", extra);
                f.label = b;
                out.push_back(f);
            }
        }
    }

    //check the hardcoded indicator strings
    //how bad a hit is depends on what file it turned up in, a script tag in an
    //html file is normal but the same bytes inside a jpeg are not
    for (size_t k = 0; k < sizeof(INDICATORS)/sizeof(INDICATORS[0]); k++) {
        size_t at = 0;
        if (!mem_find(d, n, INDICATORS[k].pat, INDICATORS[k].len, &at)) continue;

        Finding f;
        f.offset = (long long)at;
        f.label = INDICATORS[k].label;
        if (flat_img)                                  f.severity = "HIGH";
        else if (textual && !INDICATORS[k].binary_ok)  f.severity = "INFO";
        else                                           f.severity = "SUSPICIOUS";
        out.push_back(f);
    }

    //run the yara rules over the same bytes if any got loaded
    if (g_yara != NULL) {
        YaraCtx yc;
        yc.out = &out;
        yr_rules_scan_mem(g_yara, (const uint8_t *)d, n, 0, yara_cb, &yc, 0);
    }

    return out;
}

//used to sort findings worst first
static int severity_rank(const std::string &s) {
    if (s == "HIGH") return 3;
    if (s == "SUSPICIOUS") return 2;
    return 1;
}

//a deleted file that still has metadata, plus where its data physically was
struct DeletedFile {
    std::string name;
    TSK_OFF_T size;
    time_t mtime;
    time_t crtime;
    std::vector<ByteRange> extents;
    //the extent callback needs these two to turn block numbers into byte offsets
    TSK_OFF_T fs_offset;
    unsigned int block_size;
};

//everything phase 1 needs to carry around while walking the directory tree
struct Phase1Ctx {
    TSK_OFF_T fs_offset;
    unsigned int block_size;
    std::vector<DeletedFile> deleted;
    std::vector<FileReport> *reports;
    magic_t magic;
    const std::vector<Signature> *sigs;
};

//called once per block of a file, records where that block was on the disk
//aonly means tsk hands over addresses without reading the contents, which is
//all we need since we are only building a map of where the file used to live
//merges blocks that are next to each other so we get a few ranges instead of
//thousands of individual block numbers
static TSK_WALK_RET_ENUM
file_extent_cb(TSK_FS_FILE *fs_file, TSK_OFF_T off, TSK_DADDR_T addr,
               char *buf, size_t len, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr) {
    DeletedFile *df = (DeletedFile *)ptr;
    //address 0 means sparse, nothing actually stored there
    if (addr == 0 || len == 0) return TSK_WALK_CONT;

    TSK_OFF_T bstart = df->fs_offset + (TSK_OFF_T)addr * (TSK_OFF_T)df->block_size;
    if (!df->extents.empty() &&
        df->extents.back().start + df->extents.back().length == bstart) {
        df->extents.back().length += (TSK_OFF_T)len;
    } else {
        ByteRange r;
        r.start = bstart;
        r.length = (TSK_OFF_T)len;
        df->extents.push_back(r);
    }
    return TSK_WALK_CONT;
}

//formats a timestamp for printing, 0 means the filesystem never set one
static std::string fmt_time(time_t t) {
    if (t == 0) return "-";
    char b[64];
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(b);
}

//called once per file while walking the directory tree
//deleted files get written out to recovered/, live files just get scanned
//either way the contents go through phase 5
static TSK_WALK_RET_ENUM
dir_walk_cb(TSK_FS_FILE *fs_file, const char *path, void *ptr) {
    Phase1Ctx *ctx = (Phase1Ctx *)ptr;

    if (fs_file->name == NULL) return TSK_WALK_CONT;
    const char *nm = fs_file->name->name;
    //skip . and .. or we walk in circles
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) return TSK_WALK_CONT;
    //tsk makes up fake files like $MBR and $FAT1, those are not real files
    if (nm[0] == '$') return TSK_WALK_CONT;

    bool deleted = (fs_file->name->flags & TSK_FS_NAME_FLAG_UNALLOC) != 0;

    printf("%s%-30s  %s", path, nm, deleted ? "[DELETED]" : "[present]");
    if (fs_file->meta != NULL) printf("  size=%lld", (long long)fs_file->meta->size);
    else                       printf("  (metadata gone)");
    printf("\n");

    //no metadata means there is nothing to read the file with
    if (fs_file->meta == NULL || fs_file->meta->size <= 0) return TSK_WALK_CONT;

    TSK_OFF_T size = fs_file->meta->size;
    size_t readlen = (size_t)((size > (TSK_OFF_T)SCAN_CAP) ? (TSK_OFF_T)SCAN_CAP : size);

    std::vector<unsigned char> data(readlen);
    ssize_t got = tsk_fs_file_read(fs_file, 0, (char *)&data[0], readlen,
                                   TSK_FS_FILE_READ_FLAG_NONE);
    if (got <= 0) return TSK_WALK_CONT;
    //read might come back short so shrink to what we actually got
    data.resize((size_t)got);

    if (deleted) {
        mkdir("recovered", 0755);
        char outpath[512];
        snprintf(outpath, sizeof(outpath), "recovered/%s", nm);
        FILE *out = fopen(outpath, "wb");
        if (out) {
            fwrite(&data[0], 1, data.size(), out);
            fclose(out);
            printf("    -> recovered %zu bytes to %s\n", data.size(), outpath);
        }

        //record where this file's data was so phase 4 can match carved output to it
        DeletedFile df;
        df.name = nm;
        df.size = fs_file->meta->size;
        df.mtime = (time_t)fs_file->meta->mtime;
        df.crtime = (time_t)fs_file->meta->crtime;
        df.fs_offset = ctx->fs_offset;
        df.block_size = ctx->block_size;
        tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY, file_extent_cb, &df);

        if (!df.extents.empty()) {
            printf("    extents:");
            //only print the first few or the output gets unreadable
            for (size_t i = 0; i < df.extents.size() && i < 4; i++) {
                printf(" [%lld+%lld]", (long long)df.extents[i].start,
                                       (long long)df.extents[i].length);
            }
            if (df.extents.size() > 4) printf(" ... (%zu total)", df.extents.size());
            printf("\n");
        }
        ctx->deleted.push_back(df);
    }

    //scan the contents whether the file was deleted or not
    FileReport fr;
    fr.source = deleted ? "recovered" : "live";
    fr.name = nm;
    fr.size = (long long)fs_file->meta->size;
    fr.detected = "(unknown)";
    if (ctx->magic != NULL) {
        const char *desc = magic_buffer(ctx->magic, &data[0], data.size());
        if (desc) fr.detected = desc;
    }
    fr.findings = scan_content(&data[0], data.size(), fr.detected, *ctx->sigs);
    //only keep files that actually had something in them
    if (!fr.findings.empty()) ctx->reports->push_back(fr);

    return TSK_WALK_CONT;
}

//checks whether a byte offset falls inside any deleted file's old extents
//this is what lets a carved file get its original name back
static const DeletedFile *
find_owner(const std::vector<DeletedFile> &dels, TSK_OFF_T off) {
    for (size_t i = 0; i < dels.size(); i++) {
        for (size_t e = 0; e < dels[i].extents.size(); e++) {
            TSK_OFF_T s = dels[i].extents[e].start;
            TSK_OFF_T len = dels[i].extents[e].length;
            if (off >= s && off < s + len) return &dels[i];
        }
    }
    return NULL;
}

//strips anything out of a filename that would cause problems on disk
static std::string sanitize(const std::string &s) {
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        o += (isalnum(c) || c == '.' || c == '-' || c == '_') ? (char)c : '_';
    }
    return o;
}

//holds the free space runs while the block walk is building them
struct UnallocState {
    std::vector<ByteRange> runs;
    TSK_DADDR_T prev_addr;
    bool have_prev;
    TSK_OFF_T fs_offset;
    unsigned int block_size;
};

//called once per unallocated block
//blocks come in ascending order so consecutive ones get merged into one run
//instead of storing millions of separate block numbers
static TSK_WALK_RET_ENUM
block_walk_cb(const TSK_FS_BLOCK *block, void *ptr) {
    UnallocState *st = (UnallocState *)ptr;
    if (st->have_prev && block->addr == st->prev_addr + 1) {
        st->runs.back().length += st->block_size;
    } else {
        ByteRange run;
        run.start = st->fs_offset + (TSK_OFF_T)block->addr * st->block_size;
        run.length = st->block_size;
        st->runs.push_back(run);
    }
    st->prev_addr = block->addr;
    st->have_prev = true;
    return TSK_WALK_CONT;
}

//one header or footer match and which signature it belongs to
struct Hit { TSK_OFF_T offset; size_t sig_index; };
static bool hit_less(const Hit &a, const Hit &b) { return a.offset < b.offset; }

//everything we know about one carved file
struct CarveResult {
    std::string path;
    TSK_OFF_T offset;
    TSK_OFF_T size;
    std::string claimed;
    std::string detected;
    std::string method;
    std::string origname;
    std::string origtime;
    Verdict verdict;
};

//phases 3 and 4, carves files out of the free space runs then checks them
//two passes like scalpel does it, first find all the signature positions and
//then go back and pull the files out
static void carve_runs(TSK_IMG_INFO *img,
                       const std::vector<ByteRange> &runs,
                       const std::vector<Signature> &sigs,
                       const std::vector<DeletedFile> &deleted,
                       magic_t magic,
                       std::vector<FileReport> *reports) {
    const size_t CHUNK = 1024 * 1024;

    //the overlap has to cover the longest signature we are looking for
    //otherwise a signature sitting across a chunk boundary gets missed and you
    //silently lose files, which is why scalpel keeps a tail between reads
    size_t max_pat = 1;
    for (size_t i = 0; i < sigs.size(); i++) {
        if (sigs[i].header.size() > max_pat) max_pat = sigs[i].header.size();
        if (sigs[i].footer.size() > max_pat) max_pat = sigs[i].footer.size();
    }
    const size_t OVERLAP = max_pat - 1;

    std::vector<Hit> headers, footers;
    std::vector<unsigned char> buf(CHUNK + OVERLAP);

    //first pass, find every header and footer position
    for (size_t r = 0; r < runs.size(); r++) {
        TSK_OFF_T run_start = runs[r].start;
        TSK_OFF_T run_end   = run_start + runs[r].length;

        for (TSK_OFF_T pos = run_start; pos < run_end; pos += CHUNK) {
            TSK_OFF_T want = CHUNK + OVERLAP;
            if (pos + want > run_end) want = run_end - pos;
            if (want <= 0) break;

            ssize_t got = tsk_img_read(img, pos, (char *)&buf[0], (size_t)want);
            if (got <= 0) break;

            //only look for matches starting in the first chunk worth of bytes
            //the overlap tail is there so a match near the end still has enough
            //bytes after it to compare against
            size_t scan_limit = (size_t)got;
            if (scan_limit > CHUNK) scan_limit = CHUNK;

            for (size_t i = 0; i < scan_limit; i++) {
                size_t avail = (size_t)got - i;
                for (size_t s = 0; s < sigs.size(); s++) {
                    if (sig_match(&buf[i], avail, sigs[s].header, sigs[s].case_sensitive)) {
                        Hit h; h.offset = pos + (TSK_OFF_T)i; h.sig_index = s;
                        headers.push_back(h);
                    }
                    if (!sigs[s].footer.empty() &&
                        sig_match(&buf[i], avail, sigs[s].footer, sigs[s].case_sensitive)) {
                        Hit h; h.offset = pos + (TSK_OFF_T)i; h.sig_index = s;
                        footers.push_back(h);
                    }
                }
            }
        }
    }

    //sort both so the footer search below can stop early
    std::sort(headers.begin(), headers.end(), hit_less);
    std::sort(footers.begin(), footers.end(), hit_less);

    printf("Pass 1: %zu header hit(s), %zu footer hit(s)\n\n",
           headers.size(), footers.size());

    mkdir("carved", 0755);
    std::vector<CarveResult> results;
    int carved_count = 0, skipped = 0, reconciled = 0;
    //once we carve a file we trust, skip any headers that fall inside it
    TSK_OFF_T skip_until = -1;

    //second pass, pair headers with footers and write the files out
    for (size_t h = 0; h < headers.size(); h++) {
        const Hit &hit = headers[h];
        if (hit.offset < skip_until) { skipped++; continue; }

        const Signature &sig = sigs[hit.sig_index];
        TSK_OFF_T start = hit.offset;
        TSK_OFF_T end   = -1;
        std::string method;
        bool confident = false;
        bool structure_failed = false;

        //first try, parse the format itself if we know how
        if (is_jpeg_ext(sig.ext)) {
            TSK_OFF_T window = (TSK_OFF_T)sig.max_size;
            if (start + window > img->size) window = img->size - start;
            if (window > 0) {
                std::vector<unsigned char> jb((size_t)window);
                ssize_t got = tsk_img_read(img, start, (char *)&jb[0], (size_t)window);
                if (got > 0) {
                    size_t truelen = jpeg_true_length(&jb[0], (size_t)got);
                    if (truelen > 0) {
                        end = start + (TSK_OFF_T)truelen;
                        method = "structure";
                        confident = true;
                    } else {
                        //header was fine but the structure did not parse
                        //so this file is almost certainly fragmented
                        structure_failed = true;
                    }
                }
            }
        }

        //second try, look for the footer
        if (end == -1 && !sig.footer.empty()) {
            TSK_OFF_T limit = start + (TSK_OFF_T)sig.max_size;
            for (size_t f = 0; f < footers.size(); f++) {
                if (footers[f].offset <= start) continue;
                //list is sorted so once we are past the window we can stop
                if (footers[f].offset > limit) break;
                if (footers[f].sig_index != hit.sig_index) continue;

                TSK_OFF_T fo = footers[f].offset;
                if (sig.ext == "zip") {
                    //PK 05 06 is the start of the end of central directory record
                    //that record is 22 bytes plus a comment, and the comment
                    //length is in the last 2 bytes of it
                    //without this the archive comes out 18 bytes short
                    unsigned char eocd[22];
                    if (tsk_img_read(img, fo, (char *)eocd, 22) == 22) {
                        size_t comment = (size_t)eocd[20] | ((size_t)eocd[21] << 8);
                        end = fo + 22 + (TSK_OFF_T)comment;
                    } else {
                        end = fo + (TSK_OFF_T)sig.footer.size();
                    }
                } else {
                    end = fo + (TSK_OFF_T)sig.footer.size();
                }
                method = "footer";
                confident = true;
                break;
            }
        }

        //last resort, stop at the next header of any type
        //formats with no footer like .doc end up here, and without this bound
        //one of them eats the whole rest of the image
        if (end == -1) {
            TSK_OFF_T bound = start + (TSK_OFF_T)sig.max_size;
            for (size_t n = h + 1; n < headers.size(); n++) {
                if (headers[n].offset > start) {
                    if (headers[n].offset < bound) bound = headers[n].offset;
                    break;
                }
            }
            if (bound > img->size) bound = img->size;
            end = bound;
            method = "next-header";
            confident = false;
        }

        TSK_OFF_T len = end - start;
        if (len <= 0) continue;

        //check if a deleted file used to own these bytes
        const DeletedFile *owner = find_owner(deleted, start);

        char outpath[512];
        if (owner != NULL) {
            snprintf(outpath, sizeof(outpath), "carved/%05d_%s",
                     carved_count, sanitize(owner->name).c_str());
        } else {
            snprintf(outpath, sizeof(outpath), "carved/%05d.%s",
                     carved_count, sig.ext.c_str());
        }

        //keep the file in memory so we can write it and scan it without
        //reading the same bytes off the disk twice
        size_t hold = (size_t)((len > (TSK_OFF_T)SCAN_CAP) ? (TSK_OFF_T)SCAN_CAP : len);
        std::vector<unsigned char> filedata(hold);
        ssize_t held = tsk_img_read(img, start, (char *)&filedata[0], hold);
        if (held <= 0) continue;
        filedata.resize((size_t)held);

        FILE *out = fopen(outpath, "wb");
        if (out == NULL) continue;
        fwrite(&filedata[0], 1, filedata.size(), out);
        //anything bigger than the scan cap just gets streamed straight through
        if (len > (TSK_OFF_T)filedata.size()) {
            std::vector<char> tmp(65536);
            TSK_OFF_T at = start + (TSK_OFF_T)filedata.size();
            TSK_OFF_T remaining = len - (TSK_OFF_T)filedata.size();
            while (remaining > 0) {
                size_t want = tmp.size();
                if ((TSK_OFF_T)want > remaining) want = (size_t)remaining;
                ssize_t got = tsk_img_read(img, at, &tmp[0], want);
                if (got <= 0) break;
                fwrite(&tmp[0], 1, got, out);
                at += got;
                remaining -= got;
            }
        }
        fclose(out);

        CarveResult res;
        res.path = outpath;
        res.offset = start;
        res.size = len;
        res.claimed = sig.ext;
        res.method = method;
        res.verdict = V_UNKNOWN;
        res.detected = "(not checked)";
        res.origname = (owner != NULL) ? owner->name : "";
        res.origtime = (owner != NULL) ? fmt_time(owner->mtime) : "";

        if (magic != NULL) {
            const char *desc = magic_buffer(magic, &filedata[0], filedata.size());
            res.detected = (desc != NULL) ? desc : "(null)";
            res.verdict = classify(sig.ext, res.detected);
        }
        //libmagic only reads the start of the file so it calls a fragmented
        //jpeg valid, the structure parser is the one that actually knows
        if (structure_failed && res.verdict == V_VALID) res.verdict = V_FRAGMENTED;

        //cut the description down or the line wraps and gets hard to read
        std::string shortdesc = res.detected;
        if (shortdesc.size() > 40) shortdesc = shortdesc.substr(0, 37) + "...";

        printf("  %-24s %-11s %-12s off=%-9lld size=%-9lld %s\n",
               outpath, verdict_name(res.verdict), method.c_str(),
               (long long)start, (long long)len, shortdesc.c_str());

        if (owner != NULL) {
            printf("      reconciled -> original name \"%s\", modified %s\n",
                   owner->name.c_str(), res.origtime.c_str());
            reconciled++;
        }

        //run phase 5 on the carved file too
        FileReport fr;
        fr.source = "carved";
        fr.name = outpath;
        fr.size = (long long)len;
        fr.detected = res.detected;
        fr.findings = scan_content(&filedata[0], filedata.size(), res.detected, sigs);
        if (!fr.findings.empty()) reports->push_back(fr);

        results.push_back(res);
        carved_count++;
        //only skip ahead if we actually trust where this file ended
        if (confident) skip_until = end;
    }

    //count up the verdicts for the summary
    int nv = 0, np = 0, nf = 0, nm = 0, nu = 0;
    for (size_t i = 0; i < results.size(); i++) {
        switch (results[i].verdict) {
            case V_VALID:      nv++; break;
            case V_PARTIAL:    np++; break;
            case V_FRAGMENTED: nf++; break;
            case V_MISMATCH:   nm++; break;
            default:           nu++; break;
        }
    }

    printf("\n--- Carving summary ---\n");
    printf("  Candidates carved : %d  (%d header(s) suppressed as overlapping)\n",
           carved_count, skipped);
    printf("  VALID             : %d   content matches claimed type\n", nv);
    printf("  FRAGMENTED        : %d   valid header, structure does not parse\n", nf);
    printf("  PARTIAL           : %d   right type, structure incomplete\n", np);
    printf("  MISMATCH          : %d   likely false positive\n", nm);
    printf("  UNKNOWN           : %d   no validation rule for this type\n", nu);
    printf("  RECONCILED        : %d   carved data matched to a deleted filename\n",
           reconciled);

    //write the carving results out as csv
    FILE *rep = fopen("carved/report.txt", "w");
    if (rep) {
        fprintf(rep, "file,verdict,claimed_type,offset,size,end_detection,"
                     "original_name,original_mtime,detected_type\n");
        for (size_t i = 0; i < results.size(); i++) {
            //libmagic descriptions have commas in them which breaks the csv
            std::string d = results[i].detected;
            for (size_t j = 0; j < d.size(); j++) if (d[j] == ',') d[j] = ';';
            fprintf(rep, "%s,%s,%s,%lld,%lld,%s,%s,%s,%s\n",
                    results[i].path.c_str(), verdict_name(results[i].verdict),
                    results[i].claimed.c_str(),
                    (long long)results[i].offset, (long long)results[i].size,
                    results[i].method.c_str(),
                    results[i].origname.empty() ? "-" : results[i].origname.c_str(),
                    results[i].origtime.empty() ? "-" : results[i].origtime.c_str(),
                    d.c_str());
        }
        fclose(rep);
        printf("\nReport written to carved/report.txt\n");
    }
}

//prints everything phase 5 found, worst first
static void print_threat_report(std::vector<FileReport> &reports) {
    printf("\n=== Phase 5: content triage ===\n\n");

    if (reports.empty()) {
        printf("  No polyglot structure or suspicious content found.\n");
        return;
    }

    //sort the findings inside each file
    for (size_t i = 0; i < reports.size(); i++) {
        std::sort(reports[i].findings.begin(), reports[i].findings.end(),
                  [](const Finding &a, const Finding &b) {
                      return severity_rank(a.severity) > severity_rank(b.severity);
                  });
    }

    //then sort the files themselves by their worst finding
    //this puts the files worth looking at first
    std::sort(reports.begin(), reports.end(),
              [](const FileReport &a, const FileReport &b) {
                  int ra = 0, rb = 0;
                  for (size_t i = 0; i < a.findings.size(); i++)
                      ra = std::max(ra, severity_rank(a.findings[i].severity));
                  for (size_t i = 0; i < b.findings.size(); i++)
                      rb = std::max(rb, severity_rank(b.findings[i].severity));
                  return ra > rb;
              });

    int high = 0, susp = 0, info = 0;

    for (size_t i = 0; i < reports.size(); i++) {
        const FileReport &fr = reports[i];
        std::string d = fr.detected;
        if (d.size() > 52) d = d.substr(0, 49) + "...";
        printf("  [%s] %s  (%lld bytes)\n", fr.source.c_str(), fr.name.c_str(), fr.size);
        printf("      type: %s\n", d.c_str());
        for (size_t j = 0; j < fr.findings.size(); j++) {
            const Finding &f = fr.findings[j];
            printf("      %-11s %s  @ offset %lld\n",
                   f.severity.c_str(), f.label.c_str(), f.offset);
            if (f.severity == "HIGH") high++;
            else if (f.severity == "SUSPICIOUS") susp++;
            else info++;
        }
        printf("\n");
    }

    printf("--- Triage summary ---\n");
    printf("  Files with findings : %zu\n", reports.size());
    printf("  HIGH                : %d\n", high);
    printf("  SUSPICIOUS          : %d\n", susp);
    printf("  INFO                : %d\n", info);

    //same csv treatment as the carving report
    FILE *tf = fopen("threats.csv", "w");
    if (tf) {
        fprintf(tf, "source,file,size,severity,finding,offset,detected_type\n");
        for (size_t i = 0; i < reports.size(); i++) {
            std::string d = reports[i].detected;
            for (size_t j = 0; j < d.size(); j++) if (d[j] == ',') d[j] = ';';
            for (size_t j = 0; j < reports[i].findings.size(); j++) {
                const Finding &f = reports[i].findings[j];
                //yara descriptions can have commas in them too
                std::string lbl = f.label;
                for (size_t k = 0; k < lbl.size(); k++) if (lbl[k] == ',') lbl[k] = ';';
                fprintf(tf, "%s,%s,%lld,%s,%s,%lld,%s\n",
                        reports[i].source.c_str(), reports[i].name.c_str(),
                        reports[i].size, f.severity.c_str(), lbl.c_str(),
                        f.offset, d.c_str());
            }
        }
        fclose(tf);
        printf("\nTriage report written to threats.csv\n");
    }
}

//takes the image file as the first argument and an optional scalpel.conf as the second
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image-file> [scalpel.conf]\n", argv[0]);
        return 1;
    }
    const char *image_path = argv[1];

    //detect lets tsk work out the image format itself, sector size 0 means default
    TSK_IMG_INFO *img = tsk_img_open_sing(image_path, TSK_IMG_TYPE_DETECT, 0);
    if (img == NULL) {
        fprintf(stderr, "Failed to open image '%s': %s\n", image_path, tsk_error_get());
        return 1;
    }

    printf("Opened image: %s\n", image_path);
    printf("  Size:        %lld bytes\n", (long long)img->size);
    printf("  Sector size: %u bytes\n\n", img->sector_size);

    //use the passed in config if there is one, otherwise fall back to built ins
    std::vector<Signature> sigs;
    if (argc >= 3 && load_conf(argv[2], sigs)) {
        printf("Loaded %zu signature(s) from %s\n", sigs.size(), argv[2]);
    } else {
        load_default_signatures(sigs);
        printf("Using %zu built-in signature(s)\n", sigs.size());
    }

    //libmagic is optional, if it fails we just skip validation instead of quitting
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic == NULL || magic_load(magic, NULL) != 0) {
        fprintf(stderr, "Warning: libmagic unavailable, validation disabled\n");
        if (magic) { magic_close(magic); magic = NULL; }
    }

    //same with yara, missing rules is not a reason to stop
    if (yr_initialize() == ERROR_SUCCESS) {
        int nrules = 0;
        g_yara = load_yara_rules("rules", &nrules);
        if (g_yara != NULL) printf("Loaded %d YARA rule(s) from ./rules\n", nrules);
        else                printf("No YARA rules loaded (./rules missing or empty)\n");
    } else {
        fprintf(stderr, "Warning: YARA failed to initialise\n");
    }
    printf("\n");

    std::vector<FileReport> reports;
    std::vector<ByteRange> runs;
    std::vector<DeletedFile> deleted;
    TSK_FS_INFO *fs = NULL;
    TSK_VS_INFO *vs = NULL;
    TSK_OFF_T fs_offset = -1;

    //open the partition table and find the first real partition
    vs = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT);
    if (vs != NULL) {
        printf("Volume system: %s\n", tsk_vs_type_todesc(vs->vstype));
        for (const TSK_VS_PART_INFO *p = vs->part_list; p != NULL; p = p->next) {
            printf("  Partition %d: %-24s start=%lld len=%lld %s\n",
                   (int)p->addr, p->desc, (long long)p->start, (long long)p->len,
                   (p->flags & TSK_VS_PART_FLAG_ALLOC) ? "[allocated]" : "[meta]");
            //take the first allocated one rather than hardcoding an offset
            if (fs_offset == -1 && (p->flags & TSK_VS_PART_FLAG_ALLOC)) {
                fs_offset = (TSK_OFF_T)p->start * vs->block_size;
            }
        }
        printf("\n");
    } else {
        printf("No volume system found (raw data or wiped partition table).\n\n");
    }

    if (fs_offset >= 0) fs = tsk_fs_open_img(img, fs_offset, TSK_FS_TYPE_DETECT);

    if (fs != NULL) {
        printf("Filesystem: %s at offset %lld, block size %u\n\n",
               tsk_fs_type_toname(fs->ftype), (long long)fs_offset, fs->block_size);

        printf("=== Phase 1: metadata-based recovery ===\n\n");
        Phase1Ctx ctx;
        ctx.fs_offset = fs_offset;
        ctx.block_size = fs->block_size;
        ctx.reports = &reports;
        ctx.magic = magic;
        ctx.sigs = &sigs;

        //walk allocated and unallocated entries, recursing into directories
        TSK_FS_DIR_WALK_FLAG_ENUM wf = (TSK_FS_DIR_WALK_FLAG_ENUM)
            (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC |
             TSK_FS_DIR_WALK_FLAG_RECURSE);
        tsk_fs_dir_walk(fs, fs->root_inum, wf, dir_walk_cb, &ctx);
        deleted = ctx.deleted;

        printf("\n  %zu deleted file(s) with recoverable extents\n", deleted.size());

        printf("\n=== Phase 2: mapping unallocated space ===\n\n");
        UnallocState st;
        st.have_prev = false; st.prev_addr = 0;
        st.fs_offset = fs_offset; st.block_size = fs->block_size;

        //aonly again, we only want to know where the free space is
        //the carver reads the actual bytes later
        TSK_FS_BLOCK_WALK_FLAG_ENUM bf = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
            (TSK_FS_BLOCK_WALK_FLAG_UNALLOC | TSK_FS_BLOCK_WALK_FLAG_AONLY);
        if (tsk_fs_block_walk(fs, fs->first_block, fs->last_block,
                              bf, block_walk_cb, &st) != 0) {
            fprintf(stderr, "Block walk failed: %s\n", tsk_error_get());
        }
        runs = st.runs;
    } else {
        //no filesystem at all, so treat the whole image as one big free space run
        //this is what the dfrws challenge images look like, and also what a real
        //drive looks like after the partition table gets wiped
        printf("=== Phase 1: skipped (no filesystem) ===\n\n");
        printf("=== Phase 2: treating entire image as unallocated ===\n\n");
        ByteRange whole;
        whole.start = 0;
        whole.length = img->size;
        runs.push_back(whole);
    }

    TSK_OFF_T total = 0;
    for (size_t i = 0; i < runs.size(); i++) total += runs[i].length;
    printf("%zu run(s) to scan, %lld bytes (%.1f MB)\n\n",
           runs.size(), (long long)total, total / (1024.0 * 1024.0));

    printf("=== Phase 3/4: carving, validation, reconciliation ===\n\n");
    carve_runs(img, runs, sigs, deleted, magic, &reports);

    print_threat_report(reports);

    //clean everything up in reverse order of how it got opened
    if (g_yara) yr_rules_destroy(g_yara);
    yr_finalize();
    if (magic) magic_close(magic);
    if (fs) tsk_fs_close(fs);
    if (vs) tsk_vs_close(vs);
    tsk_img_close(img);
    return 0;
}