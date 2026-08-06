/*
 * documents.yar -- active content inside office documents and PDFs.
 *
 * These are the formats attackers most often use as delivery vehicles,
 * because the file itself looks like an ordinary attachment.
 */

rule office_macro_present
{
    meta:
        severity = "SUSPICIOUS"
        description = "Office document containing VBA macros"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }

        $vba1 = "_VBA_PROJECT"
        $vba2 = "vbaProject.bin"
        $vba3 = "Attribute VB_Name"

    condition:
        ($ole at 0 or $zip at 0) and any of ($vba1, $vba2, $vba3)
}

rule office_autoexec_macro
{
    meta:
        severity = "HIGH"
        description = "Macro that runs automatically when the document opens"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }

        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Workbook_Open" nocase
        $d = "AutoExec" nocase

    condition:
        ($ole at 0 or $zip at 0) and any of ($a, $b, $c, $d)
}

rule office_remote_template
{
    meta:
        severity = "HIGH"
        description = "Document referencing a remote template (payload fetched on open)"

    strings:
        $zip = { 50 4B 03 04 }
        $rel = "attachedTemplate" nocase
        $http = "http" nocase

    condition:
        $zip at 0 and $rel and $http
}

rule pdf_active_content
{
    meta:
        severity = "SUSPICIOUS"
        description = "PDF containing JavaScript or an automatic action"

    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $open = "/OpenAction"
        $aa = "/AA"
        $embed = "/EmbeddedFile"

    condition:
        $pdf at 0 and any of ($js1, $js2, $open, $aa, $embed)
}

rule pdf_launch_action
{
    meta:
        severity = "HIGH"
        description = "PDF with a Launch action -- executes an external program"

    strings:
        $pdf = "%PDF-"
        $launch = "/Launch"

    condition:
        $pdf at 0 and $launch
}