/*
 * scripts.yar -- executable script content, and script content in places
 * it has no business being.
 */

rule script_in_image
{
    meta:
        severity = "HIGH"
        description = "Script content inside an image file"

    strings:
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $gif = "GIF8"

        $php     = "<?php" nocase
        $script  = "<script" nocase
        $shebang = "#!/bin/"
        $eval    = "eval("

    condition:
        ($jpg at 0 or $png at 0 or $gif at 0) and
        any of ($php, $script, $shebang, $eval)
}

rule obfuscated_powershell
{
    meta:
        severity = "HIGH"
        description = "Encoded or obfuscated PowerShell invocation"

    strings:
        $a = "FromBase64String" nocase
        $b = "-EncodedCommand" nocase
        $c = "-nop -w hidden" nocase
        $d = "IEX(" nocase
        $e = "Invoke-Expression" nocase
        $f = "-ExecutionPolicy Bypass" nocase

    condition:
        2 of them
}

rule webshell_indicators
{
    meta:
        severity = "HIGH"
        description = "Common PHP webshell patterns"

    strings:
        $a = "eval($_POST" nocase
        $b = "eval($_GET" nocase
        $c = "system($_" nocase
        $d = "shell_exec(" nocase
        $e = "base64_decode($_" nocase
        $f = "passthru($_" nocase

    condition:
        any of them
}

rule wscript_shell_usage
{
    meta:
        severity = "SUSPICIOUS"
        description = "Windows Script Host shell object -- common in droppers"

    strings:
        $a = "WScript.Shell" nocase
        $b = "Scripting.FileSystemObject" nocase
        $c = "ADODB.Stream" nocase

    condition:
        any of them
}