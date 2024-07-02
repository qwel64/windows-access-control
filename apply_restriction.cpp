#include <windows.h>
#include <aclapi.h>

// Windowsアプリケーションのエントリーポイント
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS_W ea;

    // 制限したいパス

    LPCWSTR path = L"C:\\Path";
    
    // 現在のセキュリティ記述子を取得
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

    // 拒否アクセス制御エントリ (ACE) を作成
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(L"Everyone");

    // 新しい ACL を作成
    dwRes = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS) {
        MessageBoxW(NULL, L"SetEntriesInAcl failed", L"Error", MB_OK | MB_ICONERROR);
        LocalFree(pSD);
        return 1;
    }

    // セキュリティ記述子を更新
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

    // リソースの解放
    LocalFree(pNewDACL);
    LocalFree(pSD);

    return 0;
}