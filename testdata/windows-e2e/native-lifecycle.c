#include <windows.h>

static void write_marker(const char *suffix, const char *value) {
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

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        write_marker(".tls", "tls callback");
    }
}

/* The PE linker places this pointer into the image's TLS callback table. */
PIMAGE_TLS_CALLBACK const churro_tls_callback
    __attribute__((section(".CRT$XLB"), used)) = tls_callback;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        write_marker(".attach", "dll process attach");
    }
    return TRUE;
}

__declspec(dllexport) void Run(void) {
    write_marker(".run", "named export");
}
