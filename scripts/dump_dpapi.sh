#!/bin/bash
# dump_dpapi.sh — extract DPAPI master keys + credential blobs from a decrypted volume
# usage: ./dump_dpapi.sh [volume] [outdir]   (defaults: bl_mnt/dislocker-file, dpapi)
# deps: pytsk3 (/opt/python312 venv, or venv/bin/python3)
# out : <outdir>/masterkeys/<GUID>, <outdir>/credentials/<GUID>  (run recon_dpapi.sh first)

set -euo pipefail
VOL="${1:-bl_mnt/dislocker-file}"
OUT="${2:-dpapi}"
[ -f "$VOL" ] || { echo "[!] volume not found: $VOL"; exit 1; }
mkdir -p "$OUT/masterkeys" "$OUT/credentials"

PY=python3
if /opt/python312/bin/python3 -c 'import pytsk3' 2>/dev/null; then
    PY=/opt/python312/bin/python3
elif ! python3 -c 'import pytsk3' 2>/dev/null; then
    [ -x venv/bin/python3 ] || { echo "[!] pytsk3 missing (run extract_hives.sh once, or create a venv)"; exit 1; }
    PY=venv/bin/python3
fi

"$PY" - "$VOL" "$OUT" <<'PY'
import sys
import pytsk3

img = pytsk3.Img_Info(sys.argv[1])
fs  = pytsk3.FS_Info(img)
out = sys.argv[2]

def grab(src, dst):
    try:
        f = fs.open(path=src)
        data = f.read_random(0, f.info.meta.size)
        open(dst, 'wb').write(data)
        print(f'[+] {src} -> {dst} ({len(data)} bytes)')
    except Exception as e:
        print(f'[!] {src}: {e}')

protect = '/Windows/System32/Microsoft/Protect/S-1-5-18'
for sid_dir in (protect, protect + '/User'):
    for e in fs.open_dir(sid_dir):
        name = e.info.name.name.decode(errors='replace')
        if name in ('.', '..', 'Preferred', 'Diagnostic'):
            continue
        if e.info.meta and e.info.meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
            grab(f'{sid_dir}/{name}', f'{out}/masterkeys/{name}')

cred = '/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials'
for e in fs.open_dir(cred):
    name = e.info.name.name.decode(errors='replace')
    if name in ('.', '..'):
        continue
    if e.info.meta and e.info.meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
        grab(f'{cred}/{name}', f'{out}/credentials/{name}')
PY

echo
echo "[*] done. DPAPI files in: $OUT/masterkeys/ and $OUT/credentials/"
ls -l "$OUT/masterkeys/" "$OUT/credentials/"
