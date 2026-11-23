"""Which APIs and idioms appear in the packages the detector MISSES, versus the ones it flags?

    python -I scripts/analyze_apis.py            # development data only: M1 + M2 (both already spent)

Aggregate feature counts (module names, call names, string categories) over regex matches; never prints content.
Used to decide what the next rule set should cover. The final evaluation sample (M3) is never read by this script.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
BASE = ROOT / "data" / "malicious_real"
FLAG = 0.35
MAX_FILE = 300_000

NPM_FEATURES = {
    "require child_process": r"require\(\s*['\"](?:node:)?child_process['\"]",
    "require https/http": r"require\(\s*['\"](?:node:)?https?['\"]",
    "require net/dns": r"require\(\s*['\"](?:node:)?(?:net|dns)['\"]",
    "require os": r"require\(\s*['\"](?:node:)?os['\"]",
    "require fs": r"require\(\s*['\"](?:node:)?fs['\"]",
    "require axios/request/got/fetch": r"require\(\s*['\"](?:axios|request|got|node-fetch|superagent|needle)['\"]",
    "INLINE require('https').get(...)": r"require\(\s*['\"](?:node:)?(?:https?|net|dns|child_process)['\"]\s*\)\s*\.\s*\w+\s*\(",
    "ALIASED require then alias.method(": r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"](?:node:)?(?:https?|net|dns|child_process)['\"]\s*\)",
    "DESTRUCTURED require": r"(?:const|let|var)\s*\{[^}]*\}\s*=\s*require\(\s*['\"](?:node:)?(?:https?|child_process|fs|dns|net)['\"]",
    "process.env": r"process\.env",
    "os.hostname/userInfo/homedir": r"\.(?:hostname|userInfo|homedir|networkInterfaces)\s*\(",
    "process.cwd()/__dirname": r"process\.cwd\(\)|__dirname",
    "dns.lookup/resolve": r"\bdns\w*\.(?:lookup|resolve\w*)\s*\(",
    "new net.Socket/connect": r"\bnet\w*\.(?:Socket|connect|createConnection)|new\s+\w*Socket\s*\(",
    "exec/execSync/spawn call": r"\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(",
    "Buffer.from base64 / atob": r"Buffer\.from\([^)]*(?:base64|hex)|\batob\s*\(",
    "eval/new Function": r"\beval\s*\(|new\s+Function\s*\(",
    "discord token regex": r"\{24\}\\?\.[^\n]{0,20}\{6\}|mfa\\?\.\[",
    "discord/telegram/webhook word": r"discord|telegram|webhook",
    "browser/wallet path words": r"Local Storage|leveldb|Login Data|User Data|Cookies|wallet|\.ssh|id_rsa",
    "fetch( / XMLHttpRequest": r"\bfetch\s*\(|XMLHttpRequest",
    "obfuscated _0x names": r"_0x[0-9a-f]{4,6}",
}
PY_FEATURES = {
    "os.system/popen": r"\bos\.(?:system|popen)\s*\(",
    "subprocess call": r"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\s*\(",
    "os.startfile / ShellExecute": r"os\.startfile|ShellExecute|WinExec|CreateProcess",
    "exec( / eval(": r"\b(?:exec|eval)\s*\(",
    "urlopen / urlretrieve": r"urlopen\s*\(|urlretrieve\s*\(",
    "requests.get/post": r"requests\.(?:get|post|put)\s*\(",
    "socket use": r"\bsocket\.(?:socket|create_connection|gethostname|gethostbyname)",
    "getpass/platform/uname recon": r"getpass\.getuser|platform\.(?:node|system|uname|platform)|os\.uname|os\.getlogin|uuid\.getnode",
    "IP-lookup service": r"ipify|ifconfig\.me|ip-api|icanhazip|checkip|ipinfo|myexternalip",
    "base64 / zlib / marshal": r"\bbase64\.|\bzlib\.|\bmarshal\.",
    "ctypes / windll": r"\bctypes\b|windll",
    "discord token regex": r"\{24\}\\?\.[^\n]{0,20}\{6\}|mfa\\?\.\[",
    "discord/telegram/webhook word": r"discord|telegram|webhook",
    "browser/wallet path words": r"Local Storage|leveldb|Login Data|User Data|Cookies|wallet|\.ssh|id_rsa|APPDATA|AppData",
    "os.environ": r"os\.environ|os\.getenv",
    "cmdclass": r"cmdclass",
    "pip install at runtime": r"pip['\"]?\s*,?\s*['\"]?install|pip\s+install",
    "shell tool word (curl/wget/powershell)": r"\b(?:curl|wget|powershell|certutil|bitsadmin|nslookup)\b",
    "sys.platform / os.name branch": r"sys\.platform|os\.name",
    "open(...,'w') write": r"open\([^)]*['\"]w[b+]?['\"]",
}


def features(job):
    from mpd.loader import load_package
    group, file = job
    eco = group.split("/")[0]
    feats = NPM_FEATURES if eco == "npm" else PY_FEATURES
    try:
        pkg = load_package(BASE / file, eco, zip_password="infected")
    except Exception:  # noqa: BLE001
        return group, None
    exts = (".js", ".cjs", ".mjs", ".ts") if eco == "npm" else (".py", ".pth")
    hits = set()
    texts = []
    for path, data in list(pkg.files.items())[:300]:
        if path.lower().endswith(exts) or path in ("package.json", "setup.py"):
            texts.append(data[:MAX_FILE].decode("utf-8", "replace"))
    blob = "\n".join(texts)
    for name, rx in feats.items():
        if re.search(rx, blob):
            hits.add(name)
    if eco == "npm":
        pj = pkg.metadata.get("package_json") or {}
        sc = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
        cmd = " ".join(str(v) for k, v in sc.items() if k in ("preinstall", "install", "postinstall", "prepare"))
        if cmd:
            hits.add("HAS install-time script")
            if re.search(r"\b(?:curl|wget|nslookup|dig|ping|Invoke-WebRequest|iwr)\b", cmd, re.I):
                hits.add("script uses a network tool")
            if re.search(r"\$\(|`|%\w+%|\$\w+|\bhostname\b|\bwhoami\b|\$env:", cmd):
                hits.add("script uses substitution / host identity")
            if re.search(r"\bnode\s+\S+", cmd):
                hits.add("script launches `node <file>`")
    return group, hits


def main() -> int:
    jobs, flagged = [], []
    for which in ("M1", "M2"):
        res = json.loads((ROOT / "results" / ("malicious_eval_M1_before_root_fix.json" if which == "M1" else "malicious_eval_M2.json")).read_text())
        index = json.loads((BASE / which / "index.json").read_text())
        for sha, rec in res["samples"].items():
            if not rec["group"].endswith("malicious_intent") or not rec["v3"].get("analysable"):
                continue
            jobs.append((rec["group"], index[sha]["file"]))
            # M1 scores predate the loader fix, so re-derive "missed" from M2 only; use M1 just for feature coverage
            flagged.append(rec["v3"]["score"] >= FLAG if which == "M2" else None)
    use = [(j, fl) for j, fl in zip(jobs, flagged) if fl is not None]       # M2 only: its scores are post-fix
    print(f"{len(use)} M2 malicious_intent packages (post-fix scores): flagged vs missed feature rates\n", flush=True)
    with cf.ProcessPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(features, [j for j, _ in use], chunksize=4))
    for eco in ("npm", "pypi"):
        rows = [(g, h, fl) for (g, h), (_, fl) in zip(results, use) if g.startswith(eco) and h is not None]
        miss = [h for _, h, fl in rows if not fl]
        flag = [h for _, h, fl in rows if fl]
        print(f"== {eco}/malicious_intent: {len(flag)} flagged, {len(miss)} missed")
        names = set().union(*[h for _, h, _ in rows]) if rows else set()
        table = sorted(((sum(n in h for h in miss) / max(len(miss), 1), sum(n in h for h in flag) / max(len(flag), 1), n)
                        for n in names), reverse=True)
        print(f"   {'feature':44} {'in MISSED':>10} {'in FLAGGED':>11}")
        for m, f, n in table:
            if m >= 0.05:
                print(f"   {n:44} {m*100:9.0f}% {f*100:10.0f}%")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
