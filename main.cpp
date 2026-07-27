// main.cpp
//
// Recovers deleted files from a disk image using libtsk: opens the
// image, finds the first allocated partition via the volume system,
// opens its filesystem, and walks the full directory tree (including
// deleted entries) printing what it finds.
//
// Build:  make
// Run:    ./carver dfr-01-fat.dd

#include <tsk/libtsk.h>
#include <cstdio>
#include <cstring>
#include <sys/stat.h> 

static TSK_WALK_RET_ENUM
dir_walk_cb(TSK_FS_FILE *fs_file, const char *path, void *ptr) {
    if (fs_file->name == NULL) {
        return TSK_WALK_CONT;
    }
    // Skip the "." and ".." entries every directory has.
    if (strcmp(fs_file->name->name, ".") == 0 ||
        strcmp(fs_file->name->name, "..") == 0) {
        return TSK_WALK_CONT;
    }

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
        ssize_t bytes_read = tsk_fs_file_read(fs_file, 0, buf, size, TSK_FS_FILE_READ_FLAG_NONE);

        if (bytes_read > 0) {
            mkdir("recovered", 0755);
            char outpath[512];
            snprintf(outpath, sizeof(outpath), "recovered/%s", fs_file->name->name);
            FILE *out = fopen(outpath, "wb");
            if (out != NULL) {
                fwrite(buf, 1, bytes_read, out);
                fclose(out);
                printf("    -> recovered %zd bytes to %s\n", bytes_read, outpath);
            }
        }
        delete[] buf;
    }

    return TSK_WALK_CONT;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <image-file>\n", argv[0]);
        return 1;
    }

    const char *image_path = argv[1];

    TSK_IMG_INFO *img = tsk_img_open_sing(image_path, TSK_IMG_TYPE_DETECT, 0);
    if (img == NULL) {
        fprintf(stderr, "Failed to open image '%s': %s\n",
                image_path, tsk_error_get());
        return 1;
    }

    printf("Opened image: %s\n", image_path);
    printf("  Size:        %lld bytes\n", (long long)img->size);
    printf("  Sector size: %u bytes\n", img->sector_size);

    TSK_VS_INFO *vs = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT);
    if (vs == NULL) {
        fprintf(stderr, "No volume system found: %s\n", tsk_error_get());
        tsk_img_close(img);
        return 1;
    }

    printf("\nVolume system type: %s\n", tsk_vs_type_todesc(vs->vstype));
    printf("Block size: %u bytes\n\n", vs->block_size);

    // Find the first allocated (real, usable) partition rather than
    // hardcoding an offset -- this matches what the DFR test docs call
    // "the first partition" of each image.
    TSK_OFF_T fs_offset = -1;

    for (const TSK_VS_PART_INFO *part = vs->part_list; part != NULL; part = part->next) {
        printf("Partition %d: %s\n", (int)part->addr, part->desc);
        printf("  Start:  sector %lld (byte offset %lld)\n",
               (long long)part->start,
               (long long)part->start * vs->block_size);
        printf("  Length: %lld sectors (%lld bytes)\n",
               (long long)part->len,
               (long long)part->len * vs->block_size);
        printf("  Flags:  %s\n\n",
               (part->flags & TSK_VS_PART_FLAG_ALLOC) ? "allocated (usable)" : "unallocated/meta");

        if (fs_offset == -1 && (part->flags & TSK_VS_PART_FLAG_ALLOC)) {
            fs_offset = (TSK_OFF_T)part->start * vs->block_size;
        }
    }

    if (fs_offset == -1) {
        fprintf(stderr, "No allocated partition found.\n");
        tsk_vs_close(vs);
        tsk_img_close(img);
        return 1;
    }

    printf("Opening filesystem at byte offset %lld...\n\n", (long long)fs_offset);

    TSK_FS_INFO *fs = tsk_fs_open_img(img, fs_offset, TSK_FS_TYPE_DETECT);
    if (fs == NULL) {
        fprintf(stderr, "Failed to open filesystem: %s\n", tsk_error_get());
        tsk_vs_close(vs);
        tsk_img_close(img);
        return 1;
    }

    printf("Filesystem type: %s\n\n", tsk_fs_type_toname(fs->ftype));
    printf("Directory listing (including deleted files):\n\n");

    TSK_FS_DIR_WALK_FLAG_ENUM walk_flags = (TSK_FS_DIR_WALK_FLAG_ENUM)
        (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE);

    tsk_fs_dir_walk(fs, fs->root_inum, walk_flags, dir_walk_cb, NULL);

    tsk_fs_close(fs);
    tsk_vs_close(vs);
    tsk_img_close(img);
    return 0;
}
