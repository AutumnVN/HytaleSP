#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "zoom.h"

static HMODULE g_GameModule = NULL;
static LPVOID g_PayloadBuffer = NULL;
static uintptr_t g_CameraFovPtr = 0;
static float g_LastNormalFov = 90.0f;
static volatile unsigned char g_bZooming = 0;
static float g_ZoomFov = 30.0f;
static HWND g_hWnd = NULL;
static WNDPROC g_OriginalWndProc = NULL;
static uintptr_t g_FovResetOffset = 0; // offset from module base
static uint32_t g_FovDisp = 0;         // displacement extracted from matched movss instruction

static DWORD WINAPI ModThread(LPVOID lpParam);

void start_zoom_hook_thread(void) {
    CreateThread(NULL, 0, ModThread, NULL, 0, NULL);
}

void stop_zoom_hook_thread(void) {
    // no-op
}

// convert pattern string like "F3 0F 11 81 14 02 00 00" to int array (-1 = wildcard)
static int *pattern_to_bytes(const char *pattern, int *out_len) {
    int cap = 64;
    int *bytes = (int *)malloc(sizeof(int) * cap);
    int len = 0;

    const char *p = pattern;
    while (*p) {
        while (*p == ' ')
            p++;
        if (!*p) break;
        if (*p == '?') {
            if (len >= cap) {
                cap *= 2;
                bytes = (int *)realloc(bytes, cap * sizeof(int));
            }
            bytes[len++] = -1;
            // skip one or two ?
            p++;
            if (*p == '?') p++;
        } else {
            unsigned int val = 0;
            if (sscanf_s(p, "%x", &val) == 1) {
                if (len >= cap) {
                    cap *= 2;
                    bytes = (int *)realloc(bytes, cap * sizeof(int));
                }
                bytes[len++] = (int)val;
                // advance past the hex
                while ((*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F') || (*p >= 'a' && *p <= 'f'))
                    p++;
            } else {
                p++;
            }
        }
    }
    *out_len = len;
    return bytes;
}

static uintptr_t pattern_scan(const char *pattern, uintptr_t startOffset) {
    unsigned char *base = (unsigned char *)GetModuleHandle(NULL);
    if (!base) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    size_t size = nt->OptionalHeader.SizeOfImage;

    int patlen = 0;
    int *pat = pattern_to_bytes(pattern, &patlen);
    if (!pat || patlen == 0) {
        free(pat);
        return 0;
    }

    size_t start = 0;
    if (startOffset) start = startOffset;

    for (size_t i = start; i + (size_t)patlen < size; i++) {
        int found = 1;
        for (int j = 0; j < patlen; j++) {
            if (pat[j] == -1) continue;
            if ((unsigned char)pat[j] != base[i + j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            free(pat);
            return (uintptr_t)i; // return offset relative to module base
        }
    }

    free(pat);
    return 0;
}

// write a 5-byte relative JMP at address (assumes writable/exec perms)
static void write_rel_jmp(uintptr_t address, uintptr_t destination) {
    DWORD old;
    VirtualProtect((LPVOID)address, 8, PAGE_EXECUTE_READWRITE, &old);
    uint8_t jmp = 0xE9;
    *(uint8_t *)address = jmp;
    int32_t rel = (int32_t)(destination - (address + 5));
    *(int32_t *)(address + 1) = rel;
    // NOP remaining bytes (if any)
    *(uint8_t *)(address + 5) = 0x90;
    *(uint8_t *)(address + 6) = 0x90;
    *(uint8_t *)(address + 7) = 0x90;
    VirtualProtect((LPVOID)address, 8, old, &old);
}

static void GenerateShellcode(uint8_t *pCode, uintptr_t returnAddr, const unsigned char *origInstr, size_t instrLen) {
    // As in original: capture RCX into g_CameraFovPtr, capture XMM0 into g_LastNormalFov,
    // check g_bZooming and if true load g_ZoomFov into xmm0, restore and execute original instruction,
    // then jump back.
    // push rax
    *pCode++ = 0x50;

    // mov rax, imm64(&g_CameraFovPtr)
    *pCode++ = 0x48;
    *pCode++ = 0xB8;
    *(uintptr_t *)pCode = (uintptr_t)&g_CameraFovPtr;
    pCode += 8;
    // mov [rax], rcx
    *pCode++ = 0x48;
    *pCode++ = 0x89;
    *pCode++ = 0x08;

    // mov rax, imm64(&g_LastNormalFov)
    *pCode++ = 0x48;
    *pCode++ = 0xB8;
    *(uintptr_t *)pCode = (uintptr_t)&g_LastNormalFov;
    pCode += 8;
    // movss [rax], xmm0
    *pCode++ = 0xF3;
    *pCode++ = 0x0F;
    *pCode++ = 0x11;
    *pCode++ = 0x00;

    // mov rax, imm64(&g_bZooming)
    *pCode++ = 0x48;
    *pCode++ = 0xB8;
    *(uintptr_t *)pCode = (uintptr_t)&g_bZooming;
    pCode += 8;
    // cmp byte ptr [rax], 0
    *pCode++ = 0x80;
    *pCode++ = 0x38;
    *pCode++ = 0x00;
    // je +0x0E
    *pCode++ = 0x74;
    *pCode++ = 0x0E;

    // mov rax, imm64(&g_ZoomFov)
    *pCode++ = 0x48;
    *pCode++ = 0xB8;
    *(uintptr_t *)pCode = (uintptr_t)&g_ZoomFov;
    pCode += 8;
    // movss xmm0, [rax]
    *pCode++ = 0xF3;
    *pCode++ = 0x0F;
    *pCode++ = 0x10;
    *pCode++ = 0x00;

    // pop rax
    *pCode++ = 0x58;

    // copy original overwritten instruction bytes (keeps exact operand/register usage)
    if (origInstr && instrLen) {
        memcpy(pCode, origInstr, instrLen);
        pCode += instrLen;
    }

    // mov rax, imm64(returnAddr)
    *pCode++ = 0x48;
    *pCode++ = 0xB8;
    *(uintptr_t *)pCode = returnAddr;
    pCode += 8;
    // jmp rax
    *pCode++ = 0xFF;
    *pCode++ = 0xE0;
}

static LRESULT CALLBACK Hook_WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_MOUSEWHEEL) {
        if (g_bZooming) {
            int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            if (delta > 0)
                g_ZoomFov -= 1.0f;
            else
                g_ZoomFov += 1.0f;
            if (g_ZoomFov < 1.0f) g_ZoomFov = 1.0f;
            if (g_ZoomFov > 120.0f) g_ZoomFov = 120.0f;
            // apply immediately if we have a camera pointer
            if (g_CameraFovPtr) {
                DWORD oldProt;
                uintptr_t addr = g_CameraFovPtr + 0x214;
                VirtualProtect((LPVOID)addr, sizeof(float), PAGE_EXECUTE_READWRITE, &oldProt);
                *(float *)addr = g_ZoomFov;
                VirtualProtect((LPVOID)addr, sizeof(float), oldProt, &oldProt);
            }
        }
    }
    return CallWindowProc(g_OriginalWndProc, hWnd, uMsg, wParam, lParam);
}

static BOOL CALLBACK EnumWindowsCallback(HWND handle, LPARAM lParam) {
    DWORD dwProcId = 0;
    GetWindowThreadProcessId(handle, &dwProcId);
    if (GetCurrentProcessId() != dwProcId) return TRUE;
    if (!IsWindowVisible(handle)) return TRUE;
    g_hWnd = handle;
    return FALSE;
}

static DWORD WINAPI ModThread(LPVOID lpParam) {
    g_GameModule = GetModuleHandle(NULL);
    if (!g_GameModule) return 0;

    // locate patterns
    uintptr_t fovResetFunc = pattern_scan("56 53 48 83 EC ? 0F 29 74 24 ? 48 8B D9 F3 0F 10 83", 0);
    if (!fovResetFunc) {
        AllocConsole();
        {
            FILE *fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
        }
        printf("FovResetFunc pattern not found.\n");
        return 0;
    }

    g_FovResetOffset = pattern_scan("F3 0F 11 81 14 02 00 00", fovResetFunc);
    if (g_FovResetOffset == 0) {
        // version 5
        g_FovResetOffset = pattern_scan("F3 0F 11 81 1C 02 00 00", fovResetFunc);
    }
    if (g_FovResetOffset == 0) {
        AllocConsole();
        {
            FILE *fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
        }
        printf("g_FovResetOffset pattern not found.\n");
        return 0;
    }

    // find window
    while (g_hWnd == NULL) {
        EnumWindows(EnumWindowsCallback, 0);
        Sleep(100);
    }

    g_OriginalWndProc = (WNDPROC)SetWindowLongPtr(g_hWnd, GWLP_WNDPROC, (LONG_PTR)Hook_WndProc);

    // install hook: try to allocate near module
    uintptr_t targetAddr = (uintptr_t)g_GameModule;
    uintptr_t allocAddr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    for (uintptr_t addr = targetAddr; addr > targetAddr - 0x7FFFFFFF && addr != 0; addr -= 0x10000) {
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_FREE) {
                LPVOID p = VirtualAlloc((LPVOID)addr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) {
                    allocAddr = (uintptr_t)p;
                    break;
                }
            }
        }
    }

    if (!allocAddr) {
        // try forward search
        for (uintptr_t addr = targetAddr; addr < targetAddr + 0x7FFFFFFF; addr += 0x10000) {
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_FREE) {
                    LPVOID p = VirtualAlloc((LPVOID)addr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    if (p) {
                        allocAddr = (uintptr_t)p;
                        break;
                    }
                }
            }
        }
    }

    if (!allocAddr) {
        AllocConsole();
        {
            FILE *fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
        }
        printf("Failed to allocate memory near module. Hook not installed.\n");
        return 0;
    }

    g_PayloadBuffer = (LPVOID)allocAddr;
    uint8_t *pCode = (uint8_t *)g_PayloadBuffer;

    // read the original instruction bytes at the hook site and validate expected form
    unsigned char origInstr[8] = {0};
    unsigned char *base = (unsigned char *)g_GameModule;
    memcpy(origInstr, base + g_FovResetOffset, sizeof(origInstr));
    size_t instrLen = 8; // movss [reg+disp32], xmm -> 3 opcode + 1 modrm + 4 disp = 8 bytes
    if (!(origInstr[0] == 0xF3 && origInstr[1] == 0x0F && origInstr[2] == 0x11 && ((origInstr[3] & 0xC0) == 0x80))) {
        AllocConsole();
        {
            FILE *fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
        }
        printf("Unexpected instruction at g_FovResetOffset; aborting hook.\n");
        return 0;
    }

    uintptr_t returnAddr = (uintptr_t)g_GameModule + g_FovResetOffset + instrLen; // jump back after original instr
    // extract displacement (little-endian at origInstr+4) so Hook_WndProc can use correct offset
    g_FovDisp = *(uint32_t *)(origInstr + 4);
    GenerateShellcode(pCode, returnAddr, origInstr, instrLen);

    // Install 5-byte JMP at hookAddress
    uintptr_t hookAddress = (uintptr_t)g_GameModule + g_FovResetOffset;
    write_rel_jmp(hookAddress, allocAddr);

    // zoom loop: monitor Left Alt to toggle zooming
    unsigned char prevZoom = 0;
    while (1) {
        unsigned char isZoom = (GetAsyncKeyState(VK_LMENU) & 0x8000) ? 1 : 0;
        if (isZoom != prevZoom) {
            prevZoom = isZoom;
            g_bZooming = isZoom;
            // apply fov immediately when toggling
            if (g_CameraFovPtr) {
                uintptr_t addr = g_CameraFovPtr + (uintptr_t)g_FovDisp;
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
                    // ensure target looks like a reasonable float (0.1 - 360) before writing
                    float cur = 0.0f;
                    __try {
                        cur = *(float *)addr;
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        cur = -1.0f;
                    }
                    if (cur >= 0.1f && cur <= 360.0f) {
                        DWORD oldProt;
                        VirtualProtect((LPVOID)addr, sizeof(float), PAGE_EXECUTE_READWRITE, &oldProt);
                        if (g_bZooming) {
                            *(float *)addr = g_ZoomFov;
                        } else {
                            *(float *)addr = g_LastNormalFov;
                        }
                        VirtualProtect((LPVOID)addr, sizeof(float), oldProt, &oldProt);
                    }
                }
            }
        }
        Sleep(10);
    }

    return 0;
}

#endif // _WIN32
