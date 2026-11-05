#!/bin/bash
# recon_dpapi.sh — locate DPAPI stores in a decrypted volume and print the tree
# usage: ./recon_dpapi.sh [volume]   (default: bl_mnt/dislocker-file)
# deps: pytsk3 (/opt/python312 venv, or venv/bin/python3)
# out : scans master keys (Protect/S-1-5-18/ + User/) and systemprofile Credentials/

set -euo pipefail
VOL="${1:-bl_mnt/dislocker-file}"
[ -f "$VOL" ] || { echo "[!] volume not found: $VOL"; exit 1; }

PY=python3
if /opt/python312/bin/python3 -c 'import pytsk3' 2>/dev/null; then
    PY=/opt/python312/bin/python3
elif ! python3 -c 'import pytsk3' 2>/dev/null; then
    [ -x venv/bin/python3 ] || { echo "[!] pytsk3 missing (run extract_hives.sh once, or create a venv)"; exit 1; }
    PY=venv/bin/python3
fi

"$PY" - "$VOL" <<'PY'
import sys
import pytsk3

img = pytsk3.Img_Info(sys.argv[1])
fs  = pytsk3.FS_Info(img)

def walk(path, prefix='', depth=0, maxdepth=2):
    try:
        d = fs.open_dir(path)
    except Exception:
        print(prefix + '[!] ' + path)
        return
    entries = [e for e in d if e.info.name.name.decode(errors='replace') not in ('.', '..')]
    for i, e in enumerate(entries):
        name = e.info.name.name.decode(errors='replace')
        last = i == len(entries) - 1
        branch = '└── ' if last else '├── '
        child = prefix + ('    ' if last else '│   ')
        p = path.rstrip('/') + '/' + name
        if e.info.meta and e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            print(prefix + branch + name + '/')
            if depth < maxdepth:
                walk(p, child, depth + 1, maxdepth)
        else:
            size = e.info.meta.size if e.info.meta else 0
            print(prefix + branch + f'{name}  ({size} B)')

print('[*] DPAPI master key store (SYSTEM): /Windows/System32/Microsoft/Protect/S-1-5-18')
walk('/Windows/System32/Microsoft/Protect/S-1-5-18')
print()
print('[*] SYSTEM profile credential store: /Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials')
walk('/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials', maxdepth=0)
PY
