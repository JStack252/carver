# Carver

INTRODUCTION

Carver is an open source forensic tool that recovers deleted files from disk images and checks the recovered data for malicious content. It brings together two recovery techniques that normally live in separate tools, metadata-based recovery and signature-based carving, and adds a reconciliation step that ties their results together. That step is what lets data pulled out by carving be traced back to the file that originally held it.

The tool is meant for incident response and data recovery work. When someone breaks into a system they usually delete the tools and scripts they used, so the deleted set is often where the most useful evidence ends up. The usual workflow makes an investigator recover files with one tool, carve unallocated space with a second, and scan the output with a third. Carver does all three in a single pass over the image and writes one report.

Carver builds on code and data from The Sleuth Kit, Scalpel, libmagic and YARA. The Sleuth Kit handles all file system parsing. The carving engine follows the two-pass design from Scalpel and reads Scalpel's signature configuration format. libmagic identifies file content, and YARA supplies the rule engine for triage.

Like any investigation tool, anything Carver finds should be reproduced with a second tool before you rely on it. The Sleuth Kit's 'fls' and 'icat' commands work for checking the metadata recovery stage, and Scalpel itself works for checking carved output.

OVERVIEW

Carver analyzes a disk or file system image made by 'dd' or any similar tool that produces a raw image. Analysis runs in five phases. Each phase produces results the next phase uses, and each one degrades gracefully when the information it needs isn't there. The phases are described below in the order they run.

Phase 1, Metadata Recovery:

When a file is deleted, most file systems just mark its directory entry and data blocks as free without actually erasing either one. Until those structures get reused, the file's name, timestamps, size, and block list are all still readable.

Carver opens the volume system, finds the first allocated partition, opens the file system inside it, and walks the directory tree including the unallocated entries. For each deleted file whose metadata survived, it extracts the content to the 'recovered' directory.

Carver also records the physical byte extents each deleted file used to occupy. It doesn't need those extents to recover the file itself. They get recorded so that Phase 4 can work out which deleted file a given region of the disk belonged to.

Phase 2, Unallocated Space Mapping:

A file whose metadata was destroyed is invisible to Phase 1, but the data itself can still be sitting in unallocated space.

Carver walks every unallocated block in the file system and merges consecutive block addresses into contiguous byte ranges. Those ranges are the only regions the carving engine will look at. Restricting carving to unallocated space cuts out the biggest source of noise in normal carving: run a signature carver against a whole disk and it re-extracts every live file it hits, which leaves the investigator to sort out which results were actually deleted.

If the image has no volume system or no file system it recognizes, whether that's a raw carving target or a disk whose partition table has been wiped, Carver treats the whole image as one unallocated range and keeps going.

Phase 3, Signature Carving:

Carving recovers files by finding format signatures in raw data, without relying on any file system structures.

Carver reads a signature database in Scalpel's configuration format: file extension, case sensitivity, maximum size, header, and an optional footer. It uses a built-in set covering JPEG, PNG, GIF, PDF, ZIP, HTML and OLE documents when no configuration file is given. You can also pass Scalpel's own 'scalpel.conf' as the second argument.

Carving runs in two passes. The first pass records the position of every header and footer across the ranges from Phase 2. The second pass pairs them up and extracts the results. Reads happen in chunks with an overlap equal to the longest signature, so a signature that spans a buffer boundary doesn't get missed.

The end of each file is found by one of three methods, listed here from most reliable to least.

Structural parsing is used wherever the format allows it. For JPEG, Carver walks the segment marker chain the way a decoder would, following the declared segment lengths and correctly skipping stuffed bytes and restart markers inside the entropy-coded data, until it reaches the real end-of-image marker. This avoids the common failure where a tool stops at the first byte pair that looks like an end marker, which happens all the time inside compressed image data.

Footer matching is used for formats that have a defined trailer. For ZIP archives, Carver parses the end-of-central-directory record so the archive comment is included in the extracted length.

Next-header bounding is the fallback for formats with no footer, like OLE documents. The carve is bounded by the next signature of any type, which stops a single footerless file from swallowing the rest of the image.

Phase 4, Validation and Reconciliation:

Carved output gets validated against its own content. Each candidate goes to libmagic, and the detected type is compared against the type its signature claimed. That produces one of five verdicts. VALID means the content matches the claimed type. PARTIAL means the container is right but libmagic reports the structure is incomplete. FRAGMENTED means the header is valid but structural parsing failed, which means the file isn't contiguous on disk. MISMATCH means the content isn't the claimed type at all, so the signature matched by chance. UNKNOWN means no validation rule exists for that type yet.

The FRAGMENTED verdict comes from the structural parser, not from libmagic. libmagic only reads the start of a file, so it reports a fragmented file as valid. When a file's header parses but its internal structure doesn't, the file has almost certainly been interrupted by foreign data.

Carver then reconciles the carved output against the extents recorded back in Phase 1. If a carved candidate starts inside a range that a deleted file occupied, that candidate gets renamed with the original file name and reported with the original modification time. This gives an identity to data that carving on its own recovers anonymously, and it only works because both recovery methods run over the same image in the same pass.

Results go to 'carved/report.txt' in CSV form, including each candidate's offset and size, the method used to find its end, and the original name wherever one was recovered.

Phase 5, Content Triage:

Every file Carver touches gets checked for malicious or deceptive structure. That includes files still live on the file system, which are read into memory and scanned without being written out, along with everything recovered in Phase 1 and carved in Phase 3. It reports four classes of finding.

Embedded format signatures are a second format's magic bytes showing up inside a file. That's normal inside container formats, since archives contain files and Word documents contain images, but a foreign format inside a flat image file points to a polyglot carrier. Same-format nesting, like the JPEG thumbnail in a JPEG's Exif segment, is reported at informational level.

Appended data is found using the structural parser. For JPEG the parser establishes where the file really ends, and anything past that point was attached on purpose and is invisible to an image viewer. This is the standard way polyglot and steganographic carrier files are built.

Indicator strings cover executable stubs, shebangs, PDF action keywords, VBA project streams and encoded-command patterns. Severity is assigned relative to the host file: a script tag in an HTML document is expected, but the same bytes inside a JPEG are not.

YARA rule matches come from every '.yar' file in the 'rules' directory, which are compiled at startup and run against each file's contents. Each rule carries its own severity and description in its metadata block, so rules can be added or swapped out without touching Carver itself.

Findings are sorted most severe first, which is the order an investigator would want to work through them, and written to 'threats.csv'.

RULES

The bundled rule set lives in the 'rules' directory. The file 'polyglot.yar' covers executables and archives embedded in image files, and format headers showing up somewhere other than offset zero. The file 'scripts.yar' covers script content inside images, obfuscated PowerShell, webshell patterns and Windows Script Host usage. The file 'documents.yar' covers Office macros, macros that run automatically on open, remote template references, and PDF JavaScript and Launch actions.

You can drop additional rules into the same directory. A rule's severity and description metadata fields are used directly in Carver's output.

USAGE

    carver <image-file> [signature-config]

The signature configuration is optional and uses Scalpel's 'scalpel.conf' format. Without it, Carver falls back to its built-in signature set.

    carver disk.dd
    carver disk.dd /usr/share/scalpel/scalpel.conf

Carver writes its results into four places. The 'recovered' directory holds files recovered from surviving metadata in Phase 1. The 'carved' directory holds files carved from unallocated space in Phase 3. The file 'carved/report.txt' holds the carving results with offsets, verdicts and original names. The file 'threats.csv' holds the content triage findings.

BUILDING TEST IMAGES

You can build test images with deleted files in them without root or loop device access by using mtools, which works on FAT images directly:

    dd if=/dev/zero of=test.img bs=1M count=50
    mformat -i test.img -F ::
    mcopy -i test.img photo.jpg ::/vacation.jpg
    mdel -i test.img ::/vacation.jpg

This is handy in containerized environments where mounting isn't available.

VERIFICATION

Carver has been tested against the DFRWS 2006 File Carving Challenge, a 50MB raw image holding 32 files with no file system, published along with a full ground-truth layout and MD5 hashes for every original file.

Six files come out byte-exact, confirmed by hashing the carved output against the published hashes: scenario 3a (287,186 bytes), 2d's embedded JPEG (608,703), 3b (7,113,968), 3c (178,659), 3i (24,538,540) and 4a's ZIP archive (147,150). Scenario 3i is in the challenge specifically to trip up tools with small default size limits, and 3c is built with a decoy sector in front of the real image.

All five fragmented JPEG scenarios, 3d, 3e, 3f, 3g and 3h, are classified FRAGMENTED, and every non-fragmented JPEG scenario is carved exactly. The structural parser separates the two groups without a single error.

The metadata recovery stage has been checked separately against The Sleuth Kit's own 'icat' command, which produces byte-identical output for the same file.

KNOWN LIMITATIONS

Fragmented files are detected but not reassembled. Carver recovers the first contiguous fragment and reports the file as FRAGMENTED instead of passing off a partial file as complete. Reassembling fragmented files is still the main open problem in carving and was the whole point of the DFRWS challenges.

DFRWS scenario 3j puts a sector starting with a JPEG end-of-image marker right after the first fragment. The structural parser takes this as a legitimate end of file and reports the fragment as complete.

On FAT file systems, deletion overwrites the first character of the file name with a marker byte. The original first character can't be recovered from the directory entry, so recovered names show up as '_acation.jpg'. That's a property of the file system, not something Carver can fix.

libmagic only looks at the start of a file, so on its own it can't catch a wrong carve boundary. Structural parsing is currently implemented for JPEG only, and other formats fall back on footer matching.

OLE compound documents have no footer signature and get bounded by the next header, so they're often reported as PARTIAL.

Short indicator strings produce false positives in large binary files. A three-byte pattern will appear by chance in a few megabytes of compressed data, so indicator patterns are kept long enough to make that unlikely.

LICENSE

Carver is released under the GNU General Public License, version 2. See the LICENSE file.

Carver incorporates work from the following projects:

* The Sleuth Kit (https://github.com/sleuthkit/sleuthkit) is used as a library for all file system, volume system and metadata parsing. It's distributed under a mix of the IBM Public License, the Common Public License and the GNU General Public License, depending on the component.

* Scalpel (https://github.com/sleuthkit/scalpel) is where the signature configuration format and the two-pass carving design with buffer overlap handling come from. That design was adapted into carve_runs(). Scalpel is distributed under the GPL. It's itself a rewrite of Foremost and is no longer actively maintained, which is why its approach was reimplemented here rather than called as an external program.

* libmagic, from the file project, handles content-based type identification. It's distributed under a two-clause BSD license.

* YARA (https://github.com/VirusTotal/yara) provides the rule engine used in Phase 5. It's distributed under the BSD 3-Clause license.

Because Carver adapts code from Scalpel, which is GPL-licensed, Carver as a whole is distributed under the GPL.

INSTALL

Carver needs the development packages for its four dependencies:

    sudo apt install build-essential libtsk-dev libmagic-dev libyara-dev
    make

mtools is only needed for building test images:

    sudo apt install mtools

Jackson Stack
