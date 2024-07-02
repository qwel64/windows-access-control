#include <windows.h>
#include <aclapi.h>

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS_W ea;

    LPCWSTR path = L"C:\\Path";
    
    DWORD dwRes = GetNamedSecurityInfoW(
        path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &pOldDACL,
        NULL,
        &pSD
    );

    if (dwRes != ERROR_SUCCESS) {
        MessageBoxW(NULL, L"GetNamedSecurityInfo failed", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(L"Everyone");

    dwRes = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS) {
        MessageBoxW(NULL, L"SetEntriesInAcl failed", L"Error", MB_OK | MB_ICONERROR);
        LocalFree(pSD);
        return 1;
    }

    dwRes = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pNewDACL,
        NULL
    );

    if (dwRes != ERROR_SUCCESS) {
        MessageBoxW(NULL, L"SetNamedSecurityInfo failed", L"Error", MB_OK | MB_ICONERROR);
        LocalFree(pNewDACL);
        LocalFree(pSD);
        return 1;
    }

    MessageBoxW(NULL, L"Access restriction applied successfully", L"Success", MB_OK | MB_ICONINFORMATION);

    LocalFree(pNewDACL);
    LocalFree(pSD);

    return 0;
}
