
Carver
INTRODUCTION

Carver is an open source forensic tool that recovers deleted files from disk images and triages the recovered data for malicious content. It combines two recovery techniques that are normally provided by separate tools — metadata-based recovery and signature-based carving — and adds a reconciliation step that links their results together, so that data recovered by carving can be attributed to the file that originally held it.

Carver is intended for incident response and data recovery work. During an intrusion an attacker will commonly delete the tools and scripts they used, so the deleted set is frequently where the most interesting evidence is. Existing practice requires an investigator to recover files with one tool, carve unallocated space with a second, and scan the results with a third. Carver performs all three in a single pass over the image and produces one report.

Carver uses code and data from The Sleuth Kit, Scalpel, libmagic and YARA. The Sleuth Kit provides all file system parsing. The carving engine follows the two-pass design used by Scalpel and reads Scalpel's signature configuration format. libmagic identifies file content, and YARA provides the rule engine for content triage.

As with any investigation tool, results found with Carver should be recreated with a second tool to verify the data. The Sleuth Kit's fls and icat commands are suitable for verifying the metadata recovery stage, and Scalpel itself is suitable for verifying carved output.

OVERVIEW

Carver analyzes a disk or file system image created by dd or a similar application that creates a raw image. Analysis is performed in five phases. Each phase produces results that the following phases consume, and each phase degrades gracefully if the information it needs is unavailable.

Phase 1 — Metadata Recovery

When a file is deleted, most file systems mark its directory entry and data blocks as free without erasing either. Until those structures are reused, the file's name, timestamps, size, and block list all remain readable.

Carver opens the volume system, locates the first allocated partition, opens the file system within it, and walks the directory tree including unallocated entries. For each deleted file whose metadata survives, the file content is extracted to the recovered/ directory.

Carver also records the physical byte extents each deleted file occupied. These extents are not needed to recover the file itself; they are recorded so that Phase 4 can determine which deleted file a given region of the disk belonged to.

Phase 2 — Unallocated Space Mapping

Data whose metadata has been destroyed is invisible to Phase 1, but the data itself may still be present in unallocated space.

Carver walks every unallocated block in the file system and merges consecutive block addresses into contiguous byte ranges. These ranges are the only regions the carving engine will examine. Restricting carving to unallocated space eliminates the largest source of noise in conventional carving: a signature carver run against a whole disk will re-extract every live file it encounters, leaving the investigator to determine which results were actually deleted.

If the image contains no volume system or no recognizable file system — a raw carving target, or a disk whose partition table has been destroyed — Carver treats the entire image as one unallocated range and continues.

Phase 3 — Signature Carving

Carving recovers files by locating format signatures in raw data, without reference to file system structures.

Carver reads a signature database in Scalpel's configuration format: file extension, case sensitivity, maximum size, header, and optional footer. A built-in set covering JPEG, PNG, GIF, PDF, ZIP, HTML and OLE documents is used when no configuration file is supplied. Scalpel's own scalpel.conf may be passed as the second argument.

Carving is performed in two passes. The first pass records the position of every header and footer across the ranges from Phase 2. The second pass pairs them and extracts the results. Reads are performed in chunks with an overlap equal to the longest signature, so that a signature spanning a buffer boundary is not missed.

The end of each file is determined by one of three methods, in order of reliability:

Structural parsing is used where the format permits it. For JPEG, Carver walks the segment marker chain the way a decoder would, following declared segment lengths and correctly skipping stuffed bytes and restart markers within entropy-coded data, until it reaches the true end-of-image marker. This avoids the common failure of stopping at the first byte pair that resembles an end marker, which occurs frequently inside compressed image data.

Footer matching is used for formats with a defined trailer. For ZIP archives the end-of-central-directory record is parsed so that the archive comment is included in the extracted length.

Next-header bounding is the fallback for formats with no footer, such as OLE documents. The carve is bounded by the next signature of any type, which prevents a single footerless file from consuming the remainder of the image.

Phase 4 — Validation and Reconciliation

Carved output is validated against its own content. Each candidate is passed to libmagic and the detected type is compared against the type its signature claimed, producing one of five verdicts:

VALID — content matches the claimed type
PARTIAL — correct container, but libmagic reports the structure is incomplete
FRAGMENTED — valid header, but structural parsing failed, indicating the file is not contiguous on disk
MISMATCH — content is not the claimed type; the signature matched by chance
UNKNOWN — no validation rule exists for this type

The FRAGMENTED verdict is derived from the structural parser rather than from libmagic. libmagic reads only the beginning of a file, so it will report a fragmented file as valid. When a file's header parses but its internal structure does not, the file is almost certainly interrupted by foreign data.

Carver then reconciles carved output against the extents recorded in Phase 1. If a carved candidate begins inside a range that a deleted file occupied, that candidate is renamed with the original file name and reported with the original modification time. This attributes identity to data that carving alone recovers anonymously, and is possible only because both recovery methods run over the same image in the same pass.

Results are written to carved/report.txt in CSV form, including the offset and size of each candidate, the method used to determine its end, and the original name where one was recovered.

Phase 5 — Content Triage

Every file Carver encounters is examined for malicious or deceptive structure. This includes files that are still live on the file system, which are read into memory and scanned without being written out, as well as everything recovered in Phase 1 and carved in Phase 3.

Four classes of finding are reported:

Embedded format signatures. A second format's magic bytes appearing inside a file. This is unremarkable inside container formats — archives contain files, and Word documents contain images — but a foreign format inside a flat image file indicates a polyglot carrier. Same-format nesting, such as the JPEG thumbnail carried in a JPEG's Exif segment, is reported at informational level.

Appended data. For JPEG, the structural parser establishes where the file actually ends. Any data beyond that point was deliberately attached and is invisible to an image viewer. This is the standard construction for polyglot and steganographic carrier files.

Indicator strings. Executable stubs, shebangs, PDF action keywords, VBA project streams and encoded-command patterns. Severity is assigned relative to the host file: a script tag in an HTML document is expected, while the same bytes inside a JPEG are not.

YARA rule matches. Rules are compiled from every .yar file in the rules/ directory at startup and evaluated against each file's contents. Each rule carries its own severity and description in its metadata block, so rules can be added or replaced without modifying Carver.

Findings are sorted with the most severe first, which is the order in which an investigator would want to examine them, and written to threats.csv.

RULES

The bundled rule set is in the rules/ directory:

polyglot.yar — executables and archives embedded in image files, and format headers appearing away from offset zero
scripts.yar — script content inside images, obfuscated PowerShell, webshell patterns and Windows Script Host usage
documents.yar — Office macros, macros that execute automatically on open, remote template references, and PDF JavaScript and Launch actions

Additional rules may be placed in the same directory. A rule's severity and description metadata fields are used directly in Carver's output.

OUTPUT
recovered/          files recovered from surviving metadata (Phase 1)
carved/             files carved from unallocated space (Phase 3)
carved/report.txt   carving results with offsets, verdicts and original names
threats.csv         content triage findings
USAGE
carver <image-file> [signature-config]

The signature configuration is optional and uses Scalpel's scalpel.conf format. Without it, Carver's built-in signature set is used.

Examples:

carver disk.dd
carver disk.dd /usr/share/scalpel/scalpel.conf
BUILDING TEST IMAGES

Test images containing deleted files can be constructed without root privileges or loop device access using mtools, which manipulates FAT images directly:

dd if=/dev/zero of=test.img bs=1M count=50
mformat -i test.img -F ::
mcopy -i test.img photo.jpg ::/vacation.jpg
mdel -i test.img ::/vacation.jpg

This is useful in containerized environments where mounting is unavailable.

VERIFICATION

Carver has been evaluated against the DFRWS 2006 File Carving Challenge, a 50MB raw image containing 32 files with no file system, published together with a complete ground-truth layout.

Six files are recovered byte-exact, matching the published sizes precisely: scenario 3a (287,186 bytes), 2d's embedded JPEG (608,703), 3b (7,113,968), 3c (178,659), 3i (24,538,540) and 4a's ZIP archive (147,150). Scenario 3i is included in the challenge specifically to defeat tools with small default size limits, and 3c is constructed with a decoy sector preceding the real image.

All five fragmented JPEG scenarios — 3d, 3e, 3f, 3g and 3h — are classified FRAGMENTED, and all non-fragmented JPEG scenarios are carved exactly. The structural parser separates the two groups without error.

KNOWN LIMITATIONS

Fragmented files are detected but not reassembled. Carver recovers the first contiguous fragment and reports the file as FRAGMENTED rather than presenting a partial file as complete. Reassembly of fragmented files remains the principal open problem in carving and was the subject of the DFRWS challenges.

DFRWS scenario 3j places a sector beginning with a JPEG end-of-image marker immediately after the first fragment. The structural parser accepts this as a legitimate end of file and reports the fragment as complete.

On FAT file systems, deletion overwrites the first character of the file name with a marker byte. The original first character is not recoverable from the directory entry, so recovered names appear as _acation.jpg. This is a property of the file system, not of Carver.

libmagic examines only the beginning of a file and therefore cannot detect incorrect carve boundaries on its own. Structural parsing is currently implemented for JPEG only; other formats rely on footer matching.

OLE compound documents have no footer signature and are bounded by the next header, so they are frequently reported as PARTIAL.

LICENSE

Carver is released under the GNU General Public License, version 2. See the LICENSE file.

Carver incorporates work from the following projects:

The Sleuth Kit (https://github.com/sleuthkit/sleuthkit) is used as a library for all file system, volume system and metadata parsing. The Sleuth Kit is distributed under a combination of the IBM Public License, the Common Public License and the GNU General Public License, depending on component.
Scalpel (https://github.com/sleuthkit/scalpel) is the source of the signature configuration format and of the two-pass carving design with buffer overlap handling, which was adapted into carve_runs(). Scalpel is distributed under the GNU General Public License. Scalpel is itself a rewrite of Foremost and is no longer actively maintained, which is why its approach was reimplemented rather than invoked as an external program.
libmagic, from the file project, is used for content-based type identification. It is distributed under a two-clause BSD license.
YARA (https://github.com/VirusTotal/yara) provides the rule engine used in Phase 5. It is distributed under the BSD 3-Clause license.

Because Carver adapts code from Scalpel, which is licensed under the GPL, Carver as a whole is distributed under the GPL.

INSTALL

Carver requires development packages for its four dependencies:

sudo apt install build-essential libtsk-dev libmagic-dev libyara-dev
make

mtools is required only for building test images:

sudo apt install mtools