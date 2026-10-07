#include <windows.h>

static const char expected[] = "relocations and imports";
static const char *volatile relocated = expected;

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
