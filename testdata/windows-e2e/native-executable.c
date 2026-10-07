#include <windows.h>

static BOOL contains_argument(const WCHAR *command_line, const WCHAR *argument) {
    if (command_line == NULL) return FALSE;
    for (const WCHAR *candidate = command_line; *candidate != 0; candidate++) {
        const WCHAR *left = candidate;
        const WCHAR *right = argument;
        while (*right != 0 && *left == *right) {
            left++;
            right++;
        }
        if (*right == 0) return TRUE;
    }
    return FALSE;
}

static BOOL write_marker(const char *suffix, const char *value) {
    char prefix[MAX_PATH];
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("CHURRO_E2E_PREFIX", prefix, MAX_PATH);
    if (length == 0 || length >= MAX_PATH || length + lstrlenA(suffix) >= MAX_PATH) {
        return FALSE;
    }
    lstrcpyA(path, prefix);
    lstrcatA(path, suffix);
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(file, value, (DWORD)lstrlenA(value), &written, NULL);
    CloseHandle(file);
    return ok && written == (DWORD)lstrlenA(value);
}

int main(void) {
    const char value[] = "native executable entry";
    if (!write_marker(".entry", value)) return 2;
    if (!contains_argument(GetCommandLineW(), L"churro-exe-argument")) return 3;
    if (!write_marker(".argv", "native executable arguments")) return 4;
    /* The loader must redirect this imported exit call to thread exit. */
    ExitProcess(0);
    return 5;
}
