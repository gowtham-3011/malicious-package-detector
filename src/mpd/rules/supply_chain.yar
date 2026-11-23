/*
 * Supply-chain detection rules for mpd.
 *
 * Tags select which files a rule is applied to:
 *   python -> *.py     js -> *.js/*.cjs/*.mjs/package.json     pth -> *.pth     (no tag) -> any text file
 * The `severity`, `title` and `tactic` meta fields are read by mpd.analyzers.yara_scan.
 *
 * These overlap on purpose with the native analyzers: YARA rules are the portable form an
 * analyst can hand to another team or a scanning pipeline. Their marginal value inside this
 * tool is measured in the ablation table, not assumed.
 */

rule MPD_py_exec_of_decoded : python
{
    meta:
        severity = "high"
        title = "exec/eval of base64- or zlib-decoded data"
        tactic = "T1059.006"
    strings:
        $a = /exec\s*\(\s*(base64\.)?b64decode/
        $b = /eval\s*\(\s*compile\s*\(\s*(base64\.)?b64decode/
        $c = /exec\s*\(\s*zlib\.decompress\s*\(\s*(base64\.)?b64decode/
        $d = /exec\s*\(\s*(marshal\.loads|codecs\.decode)\s*\(/
    condition:
        any of them
}

rule MPD_npm_lifecycle_fetch_and_run : js
{
    meta:
        severity = "high"
        title = "npm lifecycle script downloads and pipes to an interpreter"
        tactic = "T1105"
    strings:
        $s = /"(pre|post)?install"\s*:\s*"[^"]*(curl|wget)[^"]*\|\s*(sudo\s+)?(ba)?sh/
    condition:
        $s
}

rule MPD_chat_webhook_exfil
{
    meta:
        severity = "high"
        title = "Discord/Slack/Telegram webhook endpoint embedded in package"
        tactic = "T1567"
    strings:
        $d = /discord(app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/
        $s = /hooks\.slack\.com\/services\//
        $t = /api\.telegram\.org\/bot[0-9]/
    condition:
        any of them
}

rule MPD_env_dump_then_post
{
    meta:
        severity = "high"
        title = "Serialises the whole environment and posts it over the network"
        tactic = "T1041"
    strings:
        $env1 = /json\.dumps\(\s*(dict\()?os\.environ/
        $env2 = /JSON\.stringify\(\s*process\.env/
        $net1 = /requests\.post|urlopen\(|urllib\.request\.Request/
        $net2 = /https?\.request\s*\(|fetch\s*\(|axios\.post/
    condition:
        ($env1 and $net1) or ($env2 and $net2)
}

rule MPD_pth_executable_line : pth
{
    meta:
        severity = "medium"
        title = ".pth file with an executable import line that decodes, executes or networks"
        tactic = "T1546"
    strings:
        $l = /(^|\n)import [^\n]*(exec\(|eval\(|b64decode|subprocess|urlopen|socket)/
    condition:
        $l
}

rule MPD_js_obfuscator_io : js
{
    meta:
        severity = "medium"
        title = "javascript-obfuscator style identifiers (_0x...)"
        tactic = "T1027"
    strings:
        $h = /_0x[0-9a-f]{4,6}\(/
    condition:
        #h > 10
}

rule MPD_shell_reverse_shell
{
    meta:
        severity = "critical"
        title = "Reverse-shell pattern"
        tactic = "T1059.004"
    strings:
        $a = /\/dev\/tcp\/[0-9]/
        $b = /bash\s+-i\s*>&/
    condition:
        any of them
}
