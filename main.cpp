// main.cpp
//
// Disk image recovery tool built on libtsk, with a signature-based
// carver adapted from Scalpel (github.com/sleuthkit/scalpel).
//
//   Phase 1: metadata-based recovery. Walk the filesystem, find deleted
//            files whose metadata survived, extract their content.
//   Phase 2: map unallocated space. Collect byte ranges belonging to no
//            live file. If there is no filesystem at all (raw carving
//            targets, wiped partition tables), fall back to treating
//            the whole image as one unallocated run.
//   Phase 3: carve. Scan those runs for file signatures and extract
//            candidates. Two-pass like Scalpel: find all header/footer
//            positions first, then extract.
//
// Build:  make
// Run:    ./carver <image>

#include <tsk/libtsk.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <sys/stat.h>
#include <string>
#include <vector>

// ===============================================================
// Signatures
// ===============================================================

struct Signature {
    std::string ext;
    bool case_sensitive;
    size_t max_size;                    // give up after this many bytes
    std::vector<unsigned char> header;
    std::vector<unsigned char> footer;  // empty == no footer, carve to max
};

// Parse a scalpel.conf-style byte string: literal characters plus
// \xNN hex escapes.  e.g. "\xff\xd8\xff\xe0" or "%PDF"
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

// Built-in defaults, drawn from Scalpel's scalpel.conf. These cover the
// file types in the DFRWS carving challenges (JPEG, ZIP, HTML, Office).
static void load_default_signatures(std::vector<Signature> &sigs) {
    struct { const char *ext; bool cs; size_t max; const char *hdr; const char *ftr; } defs[] = {
        { "jpg", true, 20000000, "\\xff\\xd8\\xff\\xe0", "\\xff\\xd9" },
        { "jpg", true, 20000000, "\\xff\\xd8\\xff\\xe1", "\\xff\\xd9" },
        { "gif", true,  5000000, "GIF87a",                "\\x00\\x3b" },
        { "gif", true,  5000000, "GIF89a",                "\\x00\\x3b" },
        { "png", true, 20000000, "\\x89PNG\\x0d\\x0a",    "IEND\\xae\\x42\\x60\\x82" },
        { "pdf", true, 50000000, "%PDF",                  "%%EOF" },
        { "zip", true, 50000000, "PK\\x03\\x04",          "PK\\x05\\x06" },
        { "htm", false, 1000000, "<html",                 "</html>" },
        { "doc", true, 50000000, "\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1", "" },
    };

    for (size_t i = 0; i < sizeof(defs)/sizeof(defs[0]); i++) {
        Signature sig;
        sig.ext = defs[i].ext;
        sig.case_sensitive = defs[i].cs;
        sig.max_size = defs[i].max;
        sig.header = parse_sig_string(defs[i].hdr);
        if (defs[i].ftr[0] != '\0') {
            sig.footer = parse_sig_string(defs[i].ftr);
        }
        sigs.push_back(sig);
    }
}

// Optional: load a real scalpel.conf. Format is
//   extension  case_sensitive(y/n)  max_size  header  [footer]
// Lines starting with # are comments.
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
// Unallocated runs
// ===============================================================

struct UnallocRun {
    TSK_OFF_T start_offset;
    TSK_OFF_T length;
};

struct UnallocState {
    std::vector<UnallocRun> runs;
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
        UnallocRun run;
        run.start_offset = st->fs_offset + (TSK_OFF_T)block->addr * st->block_size;
        run.length = st->block_size;
        st->runs.push_back(run);
    }
    st->prev_addr = block->addr;
    st->have_prev = true;
    return TSK_WALK_CONT;
}

// ===============================================================
// Phase 1 callback
// ===============================================================

static TSK_WALK_RET_ENUM
dir_walk_cb(TSK_FS_FILE *fs_file, const char *path, void *ptr) {
    if (fs_file->name == NULL) return TSK_WALK_CONT;
    if (strcmp(fs_file->name->name, ".") == 0 ||
        strcmp(fs_file->name->name, "..") == 0) return TSK_WALK_CONT;

    bool deleted = (fs_file->name->flags & TSK_FS_NAME_FLAG_UNALLOC) != 0;

    printf("%s%-30s  %s", path, fs_file->name->name,
           deleted ? "[DELETED]" : "[present]");
    if (fs_file->meta != NULL) {
        printf("  size=%lld", (long long)fs_file->meta->size);
    } else {
        printf("  (metadata gone)");
    }
    printf("\n");

    if (deleted && fs_file->meta != NULL && fs_file->meta->size > 0) {
        TSK_OFF_T size = fs_file->meta->size;
        char *buf = new char[size];
        ssize_t got = tsk_fs_file_read(fs_file, 0, buf, size, TSK_FS_FILE_READ_FLAG_NONE);
        if (got > 0) {
            mkdir("recovered", 0755);
            char outpath[512];
            snprintf(outpath, sizeof(outpath), "recovered/%s", fs_file->name->name);
            FILE *out = fopen(outpath, "wb");
            if (out) {
                fwrite(buf, 1, got, out);
                fclose(out);
                printf("    -> recovered %zd bytes to %s\n", got, outpath);
            }
        }
        delete[] buf;
    }
    return TSK_WALK_CONT;
}

// ===============================================================
// Phase 3: the carver
// ===============================================================

struct Hit {
    TSK_OFF_T offset;   // absolute offset in the image
    size_t sig_index;
};

static void carve_runs(TSK_IMG_INFO *img,
                       const std::vector<UnallocRun> &runs,
                       const std::vector<Signature> &sigs) {
    const size_t CHUNK = 1024 * 1024;

    // Overlap must cover the longest pattern, so a signature straddling
    // a chunk boundary is not missed. This is the subtle bug Scalpel
    // handles by retaining a tail region between reads.
    size_t max_pat = 1;
    for (size_t i = 0; i < sigs.size(); i++) {
        if (sigs[i].header.size() > max_pat) max_pat = sigs[i].header.size();
        if (sigs[i].footer.size() > max_pat) max_pat = sigs[i].footer.size();
    }
    const size_t OVERLAP = max_pat - 1;

    std::vector<Hit> headers, footers;
    std::vector<unsigned char> buf(CHUNK + OVERLAP);

    // ---- Pass 1: locate every header and footer -----------------
    for (size_t r = 0; r < runs.size(); r++) {
        TSK_OFF_T run_start = runs[r].start_offset;
        TSK_OFF_T run_end   = run_start + runs[r].length;

        for (TSK_OFF_T pos = run_start; pos < run_end; pos += CHUNK) {
            TSK_OFF_T want = CHUNK + OVERLAP;
            if (pos + want > run_end) want = run_end - pos;
            if (want <= 0) break;

            ssize_t got = tsk_img_read(img, pos, (char *)&buf[0], (size_t)want);
            if (got <= 0) break;

            // Only scan the first CHUNK bytes for *starts*; the overlap
            // tail exists so patterns beginning near the end still match
            // fully. Without it we would miss them and silently lose files.
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

    printf("Pass 1: %zu header hit(s), %zu footer hit(s)\n\n",
           headers.size(), footers.size());

    // ---- Pass 2: pair headers with footers and extract -----------
    mkdir("carved", 0755);
    int carved_count = 0;
    TSK_OFF_T skip_until = -1;   // avoid carving inside an earlier carve

    for (size_t h = 0; h < headers.size(); h++) {
        const Hit &hit = headers[h];
        if (hit.offset < skip_until) continue;

        const Signature &sig = sigs[hit.sig_index];
        TSK_OFF_T start = hit.offset;
        TSK_OFF_T end   = -1;

        if (!sig.footer.empty()) {
            TSK_OFF_T limit = start + (TSK_OFF_T)sig.max_size;
            for (size_t f = 0; f < footers.size(); f++) {
                if (footers[f].sig_index != hit.sig_index) continue;
                TSK_OFF_T fo = footers[f].offset;
                if (fo > start && fo <= limit) {
                    end = fo + (TSK_OFF_T)sig.footer.size();
                    break;
                }
            }
        }

        // No footer found (or signature has none): carve up to max_size.
        // These are lower confidence and worth flagging in the report.
        bool had_footer = (end != -1);
        if (!had_footer) {
            end = start + (TSK_OFF_T)sig.max_size;
            if (end > img->size) end = img->size;
        }

        TSK_OFF_T len = end - start;
        if (len <= 0) continue;

        char outpath[512];
        snprintf(outpath, sizeof(outpath), "carved/%05d.%s",
                 carved_count, sig.ext.c_str());

        FILE *out = fopen(outpath, "wb");
        if (out == NULL) continue;

        std::vector<char> data(65536);
        TSK_OFF_T remaining = len, at = start;
        while (remaining > 0) {
            size_t want = data.size();
            if ((TSK_OFF_T)want > remaining) want = (size_t)remaining;
            ssize_t got = tsk_img_read(img, at, &data[0], want);
            if (got <= 0) break;
            fwrite(&data[0], 1, got, out);
            at += got;
            remaining -= got;
        }
        fclose(out);

        printf("  carved %s  offset=%lld  size=%lld  %s\n",
               outpath, (long long)start, (long long)len,
               had_footer ? "[footer matched]" : "[NO FOOTER - low confidence]");

        carved_count++;
        skip_until = end;
    }

    printf("\nCarved %d candidate file(s) into ./carved/\n", carved_count);

    // TODO (reconciliation): cross-reference these carved offsets with
    // the cluster ranges of deleted files found in Phase 1. When they
    // overlap, the carved file can be given back its original name and
    // timestamps instead of a generic 00001.jpg.
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

    // Load signatures
    std::vector<Signature> sigs;
    if (argc >= 3 && load_conf(argv[2], sigs)) {
        printf("Loaded %zu signature(s) from %s\n\n", sigs.size(), argv[2]);
    } else {
        load_default_signatures(sigs);
        printf("Using %zu built-in signature(s)\n\n", sigs.size());
    }

    std::vector<UnallocRun> runs;
    TSK_FS_INFO *fs = NULL;
    TSK_VS_INFO *vs = NULL;

    // ---- Try to find a filesystem -------------------------------
    vs = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT);
    TSK_OFF_T fs_offset = -1;

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

    if (fs_offset >= 0) {
        fs = tsk_fs_open_img(img, fs_offset, TSK_FS_TYPE_DETECT);
    }

    if (fs != NULL) {
        printf("Filesystem: %s at offset %lld, block size %u\n\n",
               tsk_fs_type_toname(fs->ftype), (long long)fs_offset, fs->block_size);

        printf("=== Phase 1: metadata-based recovery ===\n\n");
        TSK_FS_DIR_WALK_FLAG_ENUM wf = (TSK_FS_DIR_WALK_FLAG_ENUM)
            (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC |
             TSK_FS_DIR_WALK_FLAG_RECURSE);
        tsk_fs_dir_walk(fs, fs->root_inum, wf, dir_walk_cb, NULL);

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
        // No filesystem: treat the entire image as unallocated. This is
        // the DFRWS challenge case, and also what a real drive looks like
        // after the partition table or filesystem is destroyed.
        printf("=== Phase 1: skipped (no filesystem) ===\n\n");
        printf("=== Phase 2: treating entire image as unallocated ===\n\n");
        UnallocRun whole;
        whole.start_offset = 0;
        whole.length = img->size;
        runs.push_back(whole);
    }

    TSK_OFF_T total = 0;
    for (size_t i = 0; i < runs.size(); i++) total += runs[i].length;
    printf("%zu run(s) to scan, %lld bytes (%.1f MB)\n\n",
           runs.size(), (long long)total, total / (1024.0 * 1024.0));

    // ---- Phase 3 -------------------------------------------------
    printf("=== Phase 3: signature carving ===\n\n");
    carve_runs(img, runs, sigs);

    if (fs) tsk_fs_close(fs);
    if (vs) tsk_vs_close(vs);
    tsk_img_close(img);
    return 0;
}