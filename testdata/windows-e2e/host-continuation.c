#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void __attribute__((noinline, used)) continuation_body(void) {
    char prefix[MAX_PATH];
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("CHURRO_E2E_PREFIX", prefix, MAX_PATH);
    if (length != 0 && length < MAX_PATH && length + sizeof(".continued") < MAX_PATH) {
        lstrcpyA(path, prefix);
        lstrcatA(path, ".continued");
        FILE *marker = fopen(path, "wb");
        if (marker != NULL) {
            const char value[] = "host thread continued";
            fwrite(value, 1, sizeof(value) - 1, marker);
            fclose(marker);
        }
    }
    ExitThread(0);
}

/* NtContinue jumps here without a normal call frame. Prepare the x64 ABI
   stack, then call the ordinary C function that writes the marker. */
__declspec(dllexport) __attribute__((naked)) void ChurroContinue(void) {
    __asm__ volatile (
        "andq $-16, %%rsp\n"
        "subq $32, %%rsp\n"
        "call continuation_body\n"
        "ud2\n"
        : : : "memory");
}

static int has_marker(const char *prefix, const char *suffix) {
    char path[MAX_PATH];
    if (strlen(prefix) + strlen(suffix) >= sizeof(path)) {
        return 0;
    }
    strcpy(path, prefix);
    strcat(path, suffix);
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

int main(int argc, char **argv) {
    HMODULE host = GetModuleHandleA(NULL);
    FARPROC continuation = GetProcAddress(host, "ChurroContinue");
    if (continuation == NULL) {
        fputs("host continuation export is missing\n", stderr);
        return 2;
    }
    if (argc == 2 && strcmp(argv[1], "--rva") == 0) {
        uintptr_t rva = (uintptr_t)continuation - (uintptr_t)host;
        if (rva == 0 || rva > UINT32_MAX) {
            fputs("host continuation RVA is invalid\n", stderr);
            return 2;
        }
        printf("%lu\n", (unsigned long)rva);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "--loader") != 0) {
        fputs("usage: host-continuation --rva | --loader FILE\n", stderr);
        return 2;
    }
    char prefix[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("CHURRO_E2E_PREFIX", prefix, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        fputs("CHURRO_E2E_PREFIX is required\n", stderr);
        return 2;
    }
    FILE *input = fopen(argv[2], "rb");
    if (input == NULL || fseek(input, 0, SEEK_END) != 0) {
        fputs("open loader failed\n", stderr);
        if (input != NULL) fclose(input);
        return 2;
    }
    long size = ftell(input);
    if (size <= 0 || size > 16 * 1024 * 1024 || fseek(input, 0, SEEK_SET) != 0) {
        fputs("loader size is invalid\n", stderr);
        fclose(input);
        return 2;
    }
    void *code = VirtualAlloc(NULL, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (code == NULL || fread(code, 1, (size_t)size, input) != (size_t)size) {
        fputs("read loader failed\n", stderr);
        fclose(input);
        return 2;
    }
    fclose(input);
    DWORD old_protect = 0;
    if (!VirtualProtect(code, (SIZE_T)size, PAGE_EXECUTE_READ, &old_protect) ||
        !FlushInstructionCache(GetCurrentProcess(), code, (SIZE_T)size)) {
        fputs("make loader executable failed\n", stderr);
        return 2;
    }
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)code, NULL, 0, NULL);
    if (thread == NULL) {
        fputs("start loader failed\n", stderr);
        return 2;
    }
    DWORD wait = WaitForSingleObject(thread, 45000);
    CloseHandle(thread);
    if (wait != WAIT_OBJECT_0) {
        fprintf(stderr, "continuation thread wait = %lu\n", (unsigned long)wait);
        return 2;
    }
    for (int attempt = 0; attempt < 900; attempt++) {
        if (has_marker(prefix, ".continued") && has_marker(prefix, ".imports")) {
            puts("host continuation and payload worker completed");
            return 0;
        }
        Sleep(50);
    }
    fprintf(stderr, "markers: continuation=%d payload=%d\n",
            has_marker(prefix, ".continued"), has_marker(prefix, ".imports"));
    return 2;
}
