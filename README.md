# ctf-toolkit

Scripts and payloads used in CTF and Hack The Box writeups. Each item was used in a real run. The code is shared as a reference, not as a maintained product.

## Layout

| Path | Contents |
| --- | --- |
| `recon/` | Reconnaissance helpers |
| `scripts/` | Credential and hive extraction helpers |
| `payloads/` | C payloads used during exploitation |
| `exploits/` | Per-target exploit code, currently empty |

## Recon

### adcs-mask-parser.py

Reads LDAP output for ADCS certificate templates and prints `msPKI-Certificate-Name-Flag` as unsigned hex. Use it when the signed integer in LDAP output hides which bits are set.

```sh
ldapsearch ... | python3 recon/adcs-mask-parser.py
```

### psmap.ps1

PowerShell ping sweep and port scan for a /24 subnet. Default ports: 53, 88, 135, 139, 389, 445, 3389, 5985.

```powershell
.\psmap.ps1 10.10.11
.\psmap.ps1 10.10.11 -Ports 80,443,445
```

## Scripts

### extract_hives.sh

BitLocker VMDK to raw partition, dislocker unlock, then registry hives and the recovery-key PDF. Requires `dislocker-fuse` and `pytsk3`. Needs about 16 to 20 GB of free space.

```sh
./extract_hives.sh file02.vmdk /path/to/workdir
```

### extract_all.sh

Full pipeline: sparse VMDK to raw partition, dislocker unlock, hive extraction, then DPAPI recon and dump.

```sh
./extract_all.sh file02.vmdk /path/to/workdir
```

### recon_dpapi.sh

Scans a decrypted volume for DPAPI master keys and credential blobs, then prints the tree.

```sh
./recon_dpapi.sh bl_mnt/dislocker-file
```

### dump_dpapi.sh

Extracts DPAPI master keys and credential blobs from a decrypted volume. Run `recon_dpapi.sh` first.

```sh
./dump_dpapi.sh bl_mnt/dislocker-file dpapi
```

## Payloads

### extrev.c

Winsock reverse shell DLL. Exports `sqlite3_extension_init`, so SQLite `load_extension()` runs it inside the target process.

```sh
x86_64-w64-mingw32-gcc -shared -o extrev.dll extrev.c -lws2_32
```

### loader.c

SQLite extension DLL that downloads a stageless beacon, copies it to RW memory, flips the page to RX, and runs it in a background thread.

```sh
x86_64-w64-mingw32-gcc -shared -o loader.dll loader.c -lwininet
```

### hivedump.c

Service replacement stub. Enables `SeBackupPrivilege`, saves SAM, SYSTEM, and SECURITY, copies `root.txt`, and grants `Everyone` read access.

```sh
x86_64-w64-mingw32-gcc -O2 -s -o hivedump.exe hivedump.c -ladvapi32
```

### versiondll.c

DLL sideload launcher for a 32-bit .NET service binary. On load it starts PowerShell hidden and dot-sources a script already staged at `C:\ProgramData\shell.ps1`.

```sh
i686-w64-mingw32-gcc -shared -o version.dll versiondll.c -mwindows
```

## Usage notes

- Review each script before running it. IPs, hostnames, and paths in the source are examples from the original run.
- Compile the Windows payloads yourself and check the target architecture.
- Some scripts expect `dislocker-fuse`, `pytsk3`, MinGW, or a Windows host.

## Rules

- Use only on systems you are authorized to test.
- Do not commit credentials, flags, or target-specific secrets.
- Keep new scripts self-contained and add a header with usage, dependencies, and build steps.
