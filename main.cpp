// main.cpp
//
// Disk image recovery and triage tool combining three open source projects:
//
//   * The Sleuth Kit (libtsk)  -- filesystem parsing, deleted file
//                                 metadata recovery, unallocated space
//                                 mapping.  Linked as a library.
//   * Scalpel                  -- signature database format and the
//                                 two-pass header/footer carving
//                                 approach, ported into carve_runs().
//   * libmagic (file)          -- content-based type identification.
//
// Pipeline:
//   Phase 1  metadata-based recovery of deleted files, recording the
//            byte extents each one occupied
//   Phase 2  map unallocated space, or fall back to the whole image
//   Phase 3  signature carving over those ranges, with format-aware
//            end-of-file detection for JPEG and ZIP
//   Phase 4  validate carved output, and reconcile it against Phase 1
//            extents to recover original filenames and timestamps
//   Phase 5  content triage: scan every file -- live, recovered and
//            carved -- for polyglot structure, embedded formats,
//            appended data and script/executable indicators
//
// Phase 5 exists because recovering a deleted file is only half the
// job during an incident: attackers delete their tooling, so the
// recovered set is exactly where malicious content is most likely to
// be. Recovering and triaging in one pass is the workflow that
// currently requires stitching separate tools together.
//
// Build:  make
// Run:    ./carver <image> [scalpel.conf]

#include <tsk/libtsk.h>
#include <magic.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <string>
#include <vector>
#include <algorithm>

// ===============================================================
// Basic types
// ===============================================================

struct ByteRange {
    TSK_OFF_T start;
    TSK_OFF_T length;
};

struct Signature {
    std::string ext;
    bool case_sensitive;
    size_t max_size;
    std::vector<unsigned char> header;
    std::vector<unsigned char> footer;   // empty == no footer
};

// Largest file we will hold in memory for content scanning.
static const size_t SCAN_CAP = 64u * 1024u * 1024u;

// ===============================================================
// Signature parsing / loading
// ===============================================================

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

static void load_default_signatures(std::vector<Signature> &sigs) {
    // jpg max_size is 50MB: the DFRWS challenge includes a 24.5MB JPEG
    // (scenario 3i) specifically to punish small default caps.
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
        if (defs[i].ftr[0] != '\0') sig.footer = parse_sig_string(defs[i].ftr);
        sigs.push_back(sig);
    }
}

static bool load_conf(const char *path, std::vector<Signature> &sigs) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        char ext[64], cs[8], hdr[256], ftr[256];
        unsigned long long maxsz = 0;
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

// ===============================================================
// Format-aware end detection: JPEG
// ===============================================================

static size_t jpeg_true_length(const unsigned char *d, size_t n) {
    if (n < 4 || d[0] != 0xFF || d[1] != 0xD8) return 0;

    size_t i = 2;
    while (i + 1 < n) {
        if (d[i] != 0xFF) return 0;                  // lost sync
        while (i < n && d[i] == 0xFF) i++;           // skip fill bytes
        if (i >= n) return 0;

        unsigned char marker = d[i];
        i++;

        if (marker == 0xD9) return i;                // EOI: true end
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) continue;

        if (i + 1 >= n) return 0;
        size_t seglen = ((size_t)d[i] << 8) | (size_t)d[i+1];
        if (seglen < 2 || i + seglen > n) return 0;

        if (marker == 0xDA) {                        // start of scan
            i += seglen;
            while (i + 1 < n) {
                if (d[i] == 0xFF) {
                    unsigned char m2 = d[i+1];
                    if (m2 == 0x00) { i += 2; continue; }               // stuffed
                    if (m2 >= 0xD0 && m2 <= 0xD7) { i += 2; continue; } // restart
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

static bool is_jpeg_ext(const std::string &e) {
    return e == "jpg" || e == "jpeg" || e == "jfif";
}

// ===============================================================
// libmagic validation
// ===============================================================

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

static bool contains_ci(const std::string &hay, const std::string &needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    std::string h = hay, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

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

static Verdict classify(const std::string &ext, const std::string &desc) {
    std::vector<std::string> want = expected_for(ext);
    if (want.empty()) return V_UNKNOWN;
    bool type_ok = false;
    for (size_t i = 0; i < want.size(); i++) {
        if (contains_ci(desc, want[i])) { type_ok = true; break; }
    }
    if (!type_ok) return V_MISMATCH;
    if (looks_truncated(desc)) return V_PARTIAL;
    return V_VALID;
}

// ===============================================================
// PHASE 5: content triage
// ===============================================================
//
// Three classes of finding:
//
//   1. Embedded format signatures. A second format's magic bytes
//      appearing inside a file. Normal inside containers (ZIP, OLE,
//      PDF) -- images legitimately live inside Word documents -- but
//      highly suspicious inside a flat image format.
//
//   2. Appended data. For JPEG we know the true structural end, so
//      anything past it was deliberately attached. This is the classic
//      polyglot / stego carrier construction.
//
//   3. Script and executable indicators. Severity depends on the host:
//      <script> in an HTML file is unremarkable; the same bytes inside
//      a JPEG are not.

struct Finding {
    std::string severity;    // INFO / SUSPICIOUS / HIGH
    std::string label;
    long long offset;
};

struct FileReport {
    std::string source;      // live / recovered / carved
    std::string name;
    std::string detected;
    long long size;
    std::vector<Finding> findings;
};

static bool type_is_container(const std::string &det) {
    return contains_ci(det, "Zip") || contains_ci(det, "Composite Document") ||
           contains_ci(det, "PDF") || contains_ci(det, "Microsoft") ||
           contains_ci(det, "tar") || contains_ci(det, "gzip");
}

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
    bool binary_ok;   // meaningful even in binary files
};

static const Indicator INDICATORS[] = {
    { "Windows PE executable stub", "This program cannot be run in DOS mode", 38, true },
    { "ELF executable header",      "\x7f" "ELF", 4, true },
    { "Script shebang",             "#!/", 3, false },
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

static bool mem_find(const unsigned char *d, size_t n,
                     const char *pat, size_t plen, size_t *where) {
    if (plen == 0 || n < plen) return false;
    for (size_t i = 0; i + plen <= n; i++) {
        if (memcmp(d + i, pat, plen) == 0) { *where = i; return true; }
    }
    return false;
}

static std::vector<Finding>
scan_content(const unsigned char *d, size_t n,
             const std::string &detected,
             const std::vector<Signature> &sigs) {
    std::vector<Finding> out;
    if (n == 0) return out;

    bool container = type_is_container(detected);
    bool flat_img  = type_is_flat_image(detected);
    bool textual   = type_is_text(detected);

    // --- (1) embedded format signatures -------------------------
    // Skip offset 0: that is the file's own type. Report at most one
    // hit per format so a big archive does not produce noise.
    std::vector<std::string> seen;
    for (size_t i = 1; i < n; i++) {
        for (size_t s = 0; s < sigs.size(); s++) {
            if (!sig_match(d + i, n - i, sigs[s].header, sigs[s].case_sensitive)) continue;

            if (std::find(seen.begin(), seen.end(), sigs[s].ext) != seen.end()) continue;
            seen.push_back(sigs[s].ext);

            // Same format nested in itself is routine: JPEGs carry Exif
            // thumbnails, archives contain archives. Only a *foreign*
            // format inside a flat file suggests a polyglot carrier.
            bool same_as_host = false;
            std::vector<std::string> want = expected_for(sigs[s].ext);
            for (size_t w = 0; w < want.size(); w++) {
                if (contains_ci(detected, want[w])) { same_as_host = true; break; }
            }

            Finding f;
            f.offset = (long long)i;
            f.label = "embedded " + sigs[s].ext + " signature";
            if (same_as_host)   f.severity = "INFO";        // thumbnail / nesting
            else if (container) f.severity = "INFO";        // normal nesting
            else if (flat_img)  f.severity = "HIGH";        // polyglot carrier
            else                f.severity = "SUSPICIOUS";
            out.push_back(f);
        }
    }

    // --- (2) data appended past the structural end --------------
    if (contains_ci(detected, "JPEG")) {
        size_t truelen = jpeg_true_length(d, n);
        if (truelen > 0 && truelen < n) {
            size_t extra = n - truelen;
            if (extra > 16) {          // ignore trivial padding
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

    // --- (3) script / executable indicators ---------------------
    for (size_t k = 0; k < sizeof(INDICATORS)/sizeof(INDICATORS[0]); k++) {
        size_t at = 0;
        if (!mem_find(d, n, INDICATORS[k].pat, INDICATORS[k].len, &at)) continue;

        Finding f;
        f.offset = (long long)at;
        f.label = INDICATORS[k].label;

        if (flat_img) {
            // Executable or script content inside a flat image is the
            // signature of a weaponised file.
            f.severity = "HIGH";
        } else if (textual && !INDICATORS[k].binary_ok) {
            f.severity = "INFO";       // scripts in HTML are expected
        } else if (container) {
            f.severity = "SUSPICIOUS";
        } else {
            f.severity = "SUSPICIOUS";
        }
        out.push_back(f);
    }

    return out;
}

static int severity_rank(const std::string &s) {
    if (s == "HIGH") return 3;
    if (s == "SUSPICIOUS") return 2;
    return 1;
}

// ===============================================================
// Phase 1: deleted files and their extents
// ===============================================================

struct DeletedFile {
    std::string name;
    TSK_OFF_T size;
    time_t mtime;
    time_t crtime;
    std::vector<ByteRange> extents;
    TSK_OFF_T fs_offset;         // scratch for the extent callback
    unsigned int block_size;
};

struct Phase1Ctx {
    TSK_OFF_T fs_offset;
    unsigned int block_size;
    std::vector<DeletedFile> deleted;
    std::vector<FileReport> *reports;    // Phase 5 accumulator
    magic_t magic;
    const std::vector<Signature> *sigs;
};

static TSK_WALK_RET_ENUM
file_extent_cb(TSK_FS_FILE *fs_file, TSK_OFF_T off, TSK_DADDR_T addr,
               char *buf, size_t len, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr) {
    DeletedFile *df = (DeletedFile *)ptr;
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

static std::string fmt_time(time_t t) {
    if (t == 0) return "-";
    char b[64];
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(b);
}

static TSK_WALK_RET_ENUM
dir_walk_cb(TSK_FS_FILE *fs_file, const char *path, void *ptr) {
    Phase1Ctx *ctx = (Phase1Ctx *)ptr;

    if (fs_file->name == NULL) return TSK_WALK_CONT;
    const char *nm = fs_file->name->name;
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) return TSK_WALK_CONT;
    if (nm[0] == '$') return TSK_WALK_CONT;          // TSK pseudo-files

    bool deleted = (fs_file->name->flags & TSK_FS_NAME_FLAG_UNALLOC) != 0;

    printf("%s%-30s  %s", path, nm, deleted ? "[DELETED]" : "[present]");
    if (fs_file->meta != NULL) printf("  size=%lld", (long long)fs_file->meta->size);
    else                       printf("  (metadata gone)");
    printf("\n");

    if (fs_file->meta == NULL || fs_file->meta->size <= 0) return TSK_WALK_CONT;

    TSK_OFF_T size = fs_file->meta->size;
    size_t readlen = (size_t)((size > (TSK_OFF_T)SCAN_CAP) ? (TSK_OFF_T)SCAN_CAP : size);

    std::vector<unsigned char> data(readlen);
    ssize_t got = tsk_fs_file_read(fs_file, 0, (char *)&data[0], readlen,
                                   TSK_FS_FILE_READ_FLAG_NONE);
    if (got <= 0) return TSK_WALK_CONT;
    data.resize((size_t)got);

    // Deleted files get written out; live files are scanned in memory only.
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
            for (size_t i = 0; i < df.extents.size() && i < 4; i++) {
                printf(" [%lld+%lld]", (long long)df.extents[i].start,
                                       (long long)df.extents[i].length);
            }
            if (df.extents.size() > 4) printf(" ... (%zu total)", df.extents.size());
            printf("\n");
        }
        ctx->deleted.push_back(df);
    }

    // --- Phase 5 scan -------------------------------------------
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
    if (!fr.findings.empty()) ctx->reports->push_back(fr);

    return TSK_WALK_CONT;
}

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

static std::string sanitize(const std::string &s) {
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        o += (isalnum(c) || c == '.' || c == '-' || c == '_') ? (char)c : '_';
    }
    return o;
}

// ===============================================================
// Phase 2
// ===============================================================

struct UnallocState {
    std::vector<ByteRange> runs;
    TSK_DADDR_T prev_addr;
    bool have_prev;
    TSK_OFF_T fs_offset;
    unsigned int block_size;
};

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

// ===============================================================
// Phase 3 + 4
// ===============================================================

struct Hit { TSK_OFF_T offset; size_t sig_index; };
static bool hit_less(const Hit &a, const Hit &b) { return a.offset < b.offset; }

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

static void carve_runs(TSK_IMG_INFO *img,
                       const std::vector<ByteRange> &runs,
                       const std::vector<Signature> &sigs,
                       const std::vector<DeletedFile> &deleted,
                       magic_t magic,
                       std::vector<FileReport> *reports) {
    const size_t CHUNK = 1024 * 1024;

    size_t max_pat = 1;
    for (size_t i = 0; i < sigs.size(); i++) {
        if (sigs[i].header.size() > max_pat) max_pat = sigs[i].header.size();
        if (sigs[i].footer.size() > max_pat) max_pat = sigs[i].footer.size();
    }
    const size_t OVERLAP = max_pat - 1;

    std::vector<Hit> headers, footers;
    std::vector<unsigned char> buf(CHUNK + OVERLAP);

    for (size_t r = 0; r < runs.size(); r++) {
        TSK_OFF_T run_start = runs[r].start;
        TSK_OFF_T run_end   = run_start + runs[r].length;

        for (TSK_OFF_T pos = run_start; pos < run_end; pos += CHUNK) {
            TSK_OFF_T want = CHUNK + OVERLAP;
            if (pos + want > run_end) want = run_end - pos;
            if (want <= 0) break;

            ssize_t got = tsk_img_read(img, pos, (char *)&buf[0], (size_t)want);
            if (got <= 0) break;

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

    std::sort(headers.begin(), headers.end(), hit_less);
    std::sort(footers.begin(), footers.end(), hit_less);

    printf("Pass 1: %zu header hit(s), %zu footer hit(s)\n\n",
           headers.size(), footers.size());

    mkdir("carved", 0755);
    std::vector<CarveResult> results;
    int carved_count = 0, skipped = 0, reconciled = 0;
    TSK_OFF_T skip_until = -1;

    for (size_t h = 0; h < headers.size(); h++) {
        const Hit &hit = headers[h];
        if (hit.offset < skip_until) { skipped++; continue; }

        const Signature &sig = sigs[hit.sig_index];
        TSK_OFF_T start = hit.offset;
        TSK_OFF_T end   = -1;
        std::string method;
        bool confident = false;
        bool structure_failed = false;

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
                        structure_failed = true;
                    }
                }
            }
        }

        if (end == -1 && !sig.footer.empty()) {
            TSK_OFF_T limit = start + (TSK_OFF_T)sig.max_size;
            for (size_t f = 0; f < footers.size(); f++) {
                if (footers[f].offset <= start) continue;
                if (footers[f].offset > limit) break;
                if (footers[f].sig_index != hit.sig_index) continue;

                TSK_OFF_T fo = footers[f].offset;
                if (sig.ext == "zip") {
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

        const DeletedFile *owner = find_owner(deleted, start);

        char outpath[512];
        if (owner != NULL) {
            snprintf(outpath, sizeof(outpath), "carved/%05d_%s",
                     carved_count, sanitize(owner->name).c_str());
        } else {
            snprintf(outpath, sizeof(outpath), "carved/%05d.%s",
                     carved_count, sig.ext.c_str());
        }

        // Hold the candidate in memory (up to SCAN_CAP) so it can be
        // written and content-scanned without a second read.
        size_t hold = (size_t)((len > (TSK_OFF_T)SCAN_CAP) ? (TSK_OFF_T)SCAN_CAP : len);
        std::vector<unsigned char> filedata(hold);
        ssize_t held = tsk_img_read(img, start, (char *)&filedata[0], hold);
        if (held <= 0) continue;
        filedata.resize((size_t)held);

        FILE *out = fopen(outpath, "wb");
        if (out == NULL) continue;
        fwrite(&filedata[0], 1, filedata.size(), out);
        // Anything past SCAN_CAP is streamed straight through.
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
        if (structure_failed && res.verdict == V_VALID) res.verdict = V_FRAGMENTED;

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

        // --- Phase 5 scan of the carved candidate ---------------
        FileReport fr;
        fr.source = "carved";
        fr.name = outpath;
        fr.size = (long long)len;
        fr.detected = res.detected;
        fr.findings = scan_content(&filedata[0], filedata.size(), res.detected, sigs);
        if (!fr.findings.empty()) reports->push_back(fr);

        results.push_back(res);
        carved_count++;
        if (confident) skip_until = end;
    }

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

    FILE *rep = fopen("carved/report.txt", "w");
    if (rep) {
        fprintf(rep, "file,verdict,claimed_type,offset,size,end_detection,"
                     "original_name,original_mtime,detected_type\n");
        for (size_t i = 0; i < results.size(); i++) {
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

// ===============================================================
// Phase 5 output
// ===============================================================

static void print_threat_report(std::vector<FileReport> &reports) {
    printf("\n=== Phase 5: content triage ===\n\n");

    if (reports.empty()) {
        printf("  No polyglot structure or suspicious content found.\n");
        return;
    }

    // Highest-severity files first: that is the triage order an
    // investigator actually wants.
    for (size_t i = 0; i < reports.size(); i++) {
        int worst = 0;
        for (size_t j = 0; j < reports[i].findings.size(); j++) {
            int r = severity_rank(reports[i].findings[j].severity);
            if (r > worst) worst = r;
        }
        reports[i].size = reports[i].size;   // (no-op, keeps struct simple)
        // stash rank in findings order instead of adding a field
        std::sort(reports[i].findings.begin(), reports[i].findings.end(),
                  [](const Finding &a, const Finding &b) {
                      return severity_rank(a.severity) > severity_rank(b.severity);
                  });
    }

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

    FILE *tf = fopen("threats.csv", "w");
    if (tf) {
        fprintf(tf, "source,file,size,severity,finding,offset,detected_type\n");
        for (size_t i = 0; i < reports.size(); i++) {
            std::string d = reports[i].detected;
            for (size_t j = 0; j < d.size(); j++) if (d[j] == ',') d[j] = ';';
            for (size_t j = 0; j < reports[i].findings.size(); j++) {
                const Finding &f = reports[i].findings[j];
                fprintf(tf, "%s,%s,%lld,%s,%s,%lld,%s\n",
                        reports[i].source.c_str(), reports[i].name.c_str(),
                        reports[i].size, f.severity.c_str(), f.label.c_str(),
                        f.offset, d.c_str());
            }
        }
        fclose(tf);
        printf("\nTriage report written to threats.csv\n");
    }
}

// ===============================================================

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image-file> [scalpel.conf]\n", argv[0]);
        return 1;
    }
    const char *image_path = argv[1];

    TSK_IMG_INFO *img = tsk_img_open_sing(image_path, TSK_IMG_TYPE_DETECT, 0);
    if (img == NULL) {
        fprintf(stderr, "Failed to open image '%s': %s\n", image_path, tsk_error_get());
        return 1;
    }

    printf("Opened image: %s\n", image_path);
    printf("  Size:        %lld bytes\n", (long long)img->size);
    printf("  Sector size: %u bytes\n\n", img->sector_size);

    std::vector<Signature> sigs;
    if (argc >= 3 && load_conf(argv[2], sigs)) {
        printf("Loaded %zu signature(s) from %s\n\n", sigs.size(), argv[2]);
    } else {
        load_default_signatures(sigs);
        printf("Using %zu built-in signature(s)\n\n", sigs.size());
    }

    magic_t magic = magic_open(MAGIC_NONE);
    if (magic == NULL || magic_load(magic, NULL) != 0) {
        fprintf(stderr, "Warning: libmagic unavailable, validation disabled\n");
        if (magic) { magic_close(magic); magic = NULL; }
    }

    std::vector<FileReport> reports;
    std::vector<ByteRange> runs;
    std::vector<DeletedFile> deleted;
    TSK_FS_INFO *fs = NULL;
    TSK_VS_INFO *vs = NULL;
    TSK_OFF_T fs_offset = -1;

    vs = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT);
    if (vs != NULL) {
        printf("Volume system: %s\n", tsk_vs_type_todesc(vs->vstype));
        for (const TSK_VS_PART_INFO *p = vs->part_list; p != NULL; p = p->next) {
            printf("  Partition %d: %-24s start=%lld len=%lld %s\n",
                   (int)p->addr, p->desc, (long long)p->start, (long long)p->len,
                   (p->flags & TSK_VS_PART_FLAG_ALLOC) ? "[allocated]" : "[meta]");
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

        TSK_FS_BLOCK_WALK_FLAG_ENUM bf = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
            (TSK_FS_BLOCK_WALK_FLAG_UNALLOC | TSK_FS_BLOCK_WALK_FLAG_AONLY);
        if (tsk_fs_block_walk(fs, fs->first_block, fs->last_block,
                              bf, block_walk_cb, &st) != 0) {
            fprintf(stderr, "Block walk failed: %s\n", tsk_error_get());
        }
        runs = st.runs;
    } else {
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

    if (magic) magic_close(magic);
    if (fs) tsk_fs_close(fs);
    if (vs) tsk_vs_close(vs);
    tsk_img_close(img);
    return 0;
}