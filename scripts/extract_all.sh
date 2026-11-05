#!/bin/bash
# extract_all.sh — full Odori-style pipeline: vmdk → partition → unlock → hives → DPAPI recon + dump
# usage: ./extract_all.sh file02.vmdk [workdir]
# stages: 1 sparse vmdk → raw BitLocker partition, 2 dislocker unlock,
#         3 pytsk3 hives, 4 DPAPI master keys + credential blobs

set -euo pipefail
VMDK="${1:?usage: $0 file02.vmdk [workdir]}"
WORK="${2:-$HOME/odori-lab}"
VMDK="$(realpath -m "$VMDK")"
WORK="$(realpath -m "$WORK")"
mkdir -p "$WORK"
cd "$WORK"

echo "[*] workdir: $WORK"
echo "[*] vmdk:   $VMDK"
[ -f "$VMDK" ] || { echo "[!] vmdk not found: $VMDK"; exit 1; }
echo "[*] note: extraction needs ~16-20 GB free; /tmp is often too small"
df -h "$WORK" | tail -1

# ---------- 1. sparse vmdk -> raw BitLocker partition ----------
cat > vmdk_extract.py <<'PY'
import struct, sys

def open_vmdk(path):
    f = open(path, 'rb')
    hdr = f.read(512)
    _, _, cap, gsize, _, _, ngt, _, gd, _ = struct.unpack('<IIQQQQIQQQ', hdr[4:72])
    f.seek(gd * 512)
    gd = struct.unpack('<%dI' % ngt, f.read(ngt * 4))
    return f, gd, gsize, ngt

def read_lba(f, gd, gsize, ngt, lba, n=1):
    out = b''
    for off in range(n):
        L = lba + off
        gi, go = L // gsize, L % gsize
        gte, gto = gi // ngt, gi % ngt
        gt = gd[gte]
        if gt == 0xFFFFFFFF:
            out += b'\x00' * 512; continue
        f.seek(gt * 512 + gto * 4)
        gs = struct.unpack('<I', f.read(4))[0]
        if gs == 0xFFFFFFFF:
            out += b'\x00' * 512; continue
        f.seek(gs * 512 + go * 512)
        out += f.read(512)
    return out

def main():
    vmdk = sys.argv[1]
    first, last = int(sys.argv[2]), int(sys.argv[3])
    out = sys.argv[4]
    f, gd, gsize, ngt = open_vmdk(vmdk)
    # find Basic data partition in GPT
    mbr = read_lba(f, gd, gsize, ngt, 0)
    lba1 = read_lba(f, gd, gsize, ngt, 1)
    if lba1[:8] != b'EFI PART':
        sys.exit('not a GPT disk')
    pent = struct.unpack('<Q', lba1[72:80])[0]
    nent = struct.unpack('<I', lba1[80:84])[0]
    esz  = struct.unpack('<I', lba1[84:88])[0]
    ent = read_lba(f, gd, gsize, ngt, pent, (nent * esz) // 512 + 1)
    for i in range(nent):
        e = ent[i*esz:(i+1)*esz]
        if e[0:16] == b'\x00' * 16:
            continue
        s = struct.unpack('<Q', e[32:40])[0]
        l = struct.unpack('<Q', e[40:48])[0]
        if e[0:16].hex() == 'a2a0d0ebe5b9334487c068b6b72699c7':  # Basic data
            first, last = s, l
            break
    print(f'[+] partition LBA {first}..{last}')
    nsect = last - first + 1
    with open(out, 'wb') as o:
        o.truncate(nsect * 512)
        grain_first, grain_last = first // gsize, last // gsize
        copied = holes = 0
        for gi in range(grain_first, grain_last + 1):
            gte, gto = gi // ngt, gi % ngt
            if gte >= len(gd):
                holes += 1; continue
            gt = gd[gte]
            if gt == 0xFFFFFFFF:
                holes += 1; continue
            f.seek(gt * 512 + gto * 4)
            gs = struct.unpack('<I', f.read(4))[0]
            if gs == 0xFFFFFFFF:
                holes += 1; continue
            seg_s, seg_e = max(gi*gsize, first), min(gi*gsize+gsize-1, last)
            if seg_e < seg_s: continue
            n = seg_e - seg_s + 1
            f.seek(gs * 512 + (seg_s % gsize) * 512)
            chunk = f.read(n * 512)
            o.seek((seg_s - first) * 512)
            o.write(chunk)
            copied += n
    print(f'[+] copied {copied} sectors, {holes} zero grains -> {out}')

if __name__ == '__main__':
    main()
PY

python3 vmdk_extract.py "$VMDK" 0 0 raw_partition.raw

# ---------- 2. dislocker unlock ----------
if [ ! -f bl_mnt/dislocker-file ]; then
    mkdir -p bl_mnt
    DISLOCKER="${DISLOCKER:-dislocker-fuse}"
    if ! command -v "$DISLOCKER" >/dev/null 2>&1; then
        for cand in /tmp/opencode-1000/dislocker-build/src/dislocker-fuse \
                    "$HOME/dislocker-build/src/dislocker-fuse"; do
            if [ -x "$cand" ]; then
                DISLOCKER="$cand"
                break
            fi
        done
        export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$(dirname "$DISLOCKER")"
    fi
    if ! command -v "$DISLOCKER" >/dev/null 2>&1 && [ ! -x "$DISLOCKER" ]; then
        echo "[!] dislocker-fuse not found; build first (see post Appendix A)"
        exit 1
    fi
    echo "[*] unlocking with --user-password=123456789 ($DISLOCKER)"
    "$DISLOCKER" --user-password=123456789 -V raw_partition.raw -- bl_mnt
fi

# ---------- 3. pytsk3 hive extraction ----------
if ! python3 -c 'import pytsk3' 2>/dev/null; then
    echo "[*] installing pytsk3 (venv)"
    python3 -m venv venv
    venv/bin/pip -q install pytsk3
    PY=venv/bin/python3
else
    PY=python3
fi

mkdir -p hives
$PY - <<'PY'
import pytsk3, os
img = pytsk3.Img_Info('bl_mnt/dislocker-file')
fs  = pytsk3.FS_Info(img)
paths = {
    '/Windows/System32/config/SYSTEM':   'hives/SYSTEM',
    '/Windows/System32/config/SAM':      'hives/SAM',
    '/Windows/System32/config/SECURITY': 'hives/SECURITY',
    '/Windows/System32/config/SOFTWARE': 'hives/SOFTWARE',
    '/Windows/System32/config/DEFAULT':  'hives/DEFAULT',
    '/Users/Administrator/Documents/recovery_key.pdf': 'hives/recovery_key.pdf',
}
for src, dst in paths.items():
    try:
        f = fs.open(path=src)
        data = f.read_random(0, f.info.meta.size)
        open(dst, 'wb').write(data)
        print(f'[+] {src} -> {dst} ({len(data)} bytes)')
    except Exception as e:
        print(f'[-] {src}: {e}')
PY

# ---------- 4. DPAPI master keys + credential blobs ----------
mkdir -p dpapi/masterkeys dpapi/credentials
$PY - <<'PY'
import pytsk3

img = pytsk3.Img_Info('bl_mnt/dislocker-file')
fs  = pytsk3.FS_Info(img)

def walk(path, depth=0, maxdepth=2):
    try:
        d = fs.open_dir(path)
    except Exception:
        return
    for e in d:
        name = e.info.name.name.decode(errors='replace')
        if name in ('.', '..'):
            continue
        p = path.rstrip('/') + '/' + name
        if e.info.meta and e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            if depth < maxdepth:
                walk(p, depth + 1, maxdepth)
        else:
            print(f'  {p}')

print('[*] DPAPI master key store (SYSTEM):')
walk('/Windows/System32/Microsoft/Protect/S-1-5-18')
print('[*] SYSTEM profile credential store:')
walk('/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials', maxdepth=0)

def grab(src, dst):
    try:
        f = fs.open(path=src)
        data = f.read_random(0, f.info.meta.size)
        open(dst, 'wb').write(data)
        print(f'[+] {src} -> {dst} ({len(data)} bytes)')
    except Exception as e:
        print(f'[-] {src}: {e}')

protect = '/Windows/System32/Microsoft/Protect/S-1-5-18'
for sid_dir in (protect, protect + '/User'):
    for e in fs.open_dir(sid_dir):
        name = e.info.name.name.decode(errors='replace')
        if name in ('.', '..', 'Preferred', 'Diagnostic'):
            continue
        if e.info.meta and e.info.meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
            grab(f'{sid_dir}/{name}', f'dpapi/masterkeys/{name}')

cred = '/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials'
for e in fs.open_dir(cred):
    name = e.info.name.name.decode(errors='replace')
    if name in ('.', '..'):
        continue
    if e.info.meta and e.info.meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
        grab(f'{cred}/{name}', f'dpapi/credentials/{name}')
PY

echo
echo "[*] done. Hives in: $WORK/hives/   DPAPI in: $WORK/dpapi/"
ls -l "$WORK/hives/" "$WORK/dpapi/masterkeys/" "$WORK/dpapi/credentials/"
