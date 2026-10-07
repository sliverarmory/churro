#include <windows.h>

static const char expected[] = "relocations and imports";
static const char *volatile relocated = expected;

static void write_argument_marker(const char *suffix, const char *value) {
    char prefix[MAX_PATH];
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("CHURRO_E2E_PREFIX", prefix, MAX_PATH);
    if (length == 0 || length >= MAX_PATH || length + lstrlenA(suffix) >= MAX_PATH) {
        return;
    }
    lstrcpyA(path, prefix);
    lstrcatA(path, suffix);
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written;
    WriteFile(file, value, (DWORD)lstrlenA(value), &written, NULL);
    CloseHandle(file);
}

__declspec(dllexport) void RunImports(void) {
    char prefix[MAX_PATH];
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("CHURRO_E2E_PREFIX", prefix, MAX_PATH);
    if (length == 0 || length >= MAX_PATH || length + sizeof(".imports") >= MAX_PATH) {
        return;
    }
    if (lstrcmpA(relocated, expected) != 0 || GetSystemMetrics(SM_CXSCREEN) < 0) {
        return;
    }
    lstrcpyA(path, prefix);
    lstrcatA(path, ".imports");
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written;
    WriteFile(file, expected, (DWORD)(sizeof(expected) - 1), &written, NULL);
    CloseHandle(file);
}

__declspec(dllexport) void RunArgsA(const char *argument) {
    if (argument != NULL && lstrcmpA(argument, "churro-ansi-argument") == 0) {
        write_argument_marker(".args-ansi", "ANSI argument received");
    }
}

__declspec(dllexport) void RunArgsACP(const char *argument) {
    const wchar_t text[] = {'c', 'a', 'f', 0x00e9, 0};
    char expected_acp[32];
    BOOL used_default = FALSE;
    if (GetACP() == CP_UTF8) {
        return;
    }
    int length = WideCharToMultiByte(CP_ACP, 0, text, -1,
                                     expected_acp, sizeof(expected_acp), NULL, &used_default);
    if (length > 0 && !used_default && argument != NULL &&
        lstrcmpA(argument, expected_acp) == 0) {
        write_argument_marker(".args-acp", "ANSI code page argument received");
    }
}

__declspec(dllexport) void RunArgsW(const wchar_t *argument) {
    if (argument != NULL && lstrcmpW(argument, L"churro-wide-argument") == 0) {
        write_argument_marker(".args-wide", "Unicode argument received");
    }
}
