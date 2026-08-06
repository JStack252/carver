/*
 * polyglot.yar -- files that are validly more than one format.
 *
 * The pattern these rules look for: a file whose magic bytes at offset 0
 * identify it as a benign flat format (image), but which also contains a
 * second format's signature further in. Image viewers stop reading at the
 * image's own end marker, so the trailing payload is invisible to the user
 * while remaining fully extractable by any tool that looks for it.
 */

rule embedded_pe_in_image
{
    meta:
        severity = "HIGH"
        description = "Windows executable embedded in an image file"

    strings:
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $gif = "GIF8"
        $dos_stub = "This program cannot be run in DOS mode"

    condition:
        ($jpg at 0 or $png at 0 or $gif at 0) and $dos_stub
}

rule embedded_elf_in_image
{
    meta:
        severity = "HIGH"
        description = "Linux executable embedded in an image file"

    strings:
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $gif = "GIF8"
        $elf = { 7F 45 4C 46 }

    condition:
        ($jpg at 0 or $png at 0 or $gif at 0) and $elf and @elf > 0
}

rule archive_appended_to_image
{
    meta:
        severity = "HIGH"
        description = "Archive appended to an image (classic polyglot carrier)"

    strings:
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $gif = "GIF8"
        $zip = { 50 4B 03 04 }
        $rar = "Rar!"
        $sevenz = { 37 7A BC AF 27 1C }

    condition:
        ($jpg at 0 or $png at 0 or $gif at 0) and
        (
            ($zip and @zip > 1024) or
            ($rar and @rar > 1024) or
            ($sevenz and @sevenz > 1024)
        )
}

rule pdf_not_at_offset_zero
{
    meta:
        severity = "SUSPICIOUS"
        description = "PDF header away from offset 0 -- many readers still accept it"

    strings:
        $pdf = "%PDF-"

    condition:
        $pdf and @pdf > 0 and @pdf < 1024 and not ($pdf at 0)
}