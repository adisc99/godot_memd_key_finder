/*
 * Godot Memory Dump AES-256 Key Finder
 * Author: adisc (https://github.com/adisc99)
 *
 * Description:
 *   High-performance, multi-threaded C tool designed to recover Godot Engine 
 *   AES-256 encryption keys from game executables or memory dumps (RAM).
 *   Supports standalone and embedded PCK archives (Godot 3.x and 4.x, formats v1/v2/v3),
 *   encrypted pack directories (PACK_DIR_ENCRYPTED), and individual encrypted files.
 *
 * Requirements / Platform:
 *   - Windows x64 (Native Windows API: CreateProcessA, MiniDumpWriteDump, OpenMP).
 *   - OpenSSL libcrypto (libcrypto-3-x64.dll, libcrypto.dll, or libcrypto-1_1-x64.dll).
 *   - dbghelp.dll (standard Windows system library for minidumps).
 *
 * Compilation (MinGW-w64 on Windows):
 *   gcc -O3 -fopenmp godot_memd_key_finder.c -o godot_memd_key_finder.exe
 *
 * Compilation (Cross-compiling from Linux targeting Windows x64):
 *   x86_64-w64-mingw32-gcc -O3 -fopenmp godot_memd_key_finder.c -o godot_memd_key_finder.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <omp.h>
#include <time.h>

#define TOOL_VER "1.4"

/* OpenSSL libcrypto function pointers loaded dynamically at runtime */
typedef void* (*EVP_CIPHER_CTX_new_fn)(void);
typedef void (*EVP_CIPHER_CTX_free_fn)(void*);
typedef int (*EVP_CIPHER_CTX_reset_fn)(void*);
typedef void* (*EVP_aes_256_cfb128_fn)(void);
typedef int (*EVP_DecryptInit_ex_fn)(void*, void*, void*, const unsigned char*, const unsigned char*);
typedef int (*EVP_DecryptUpdate_fn)(void*, unsigned char*, int*, const unsigned char*, int);
typedef unsigned char* (*MD5_fn)(const unsigned char*, size_t, unsigned char*);

static EVP_CIPHER_CTX_new_fn p_EVP_CIPHER_CTX_new = NULL;
static EVP_CIPHER_CTX_free_fn p_EVP_CIPHER_CTX_free = NULL;
static EVP_CIPHER_CTX_reset_fn p_EVP_CIPHER_CTX_reset = NULL;
static EVP_aes_256_cfb128_fn p_EVP_aes_256_cfb128 = NULL;
static EVP_DecryptInit_ex_fn p_EVP_DecryptInit_ex = NULL;
static EVP_DecryptUpdate_fn p_EVP_DecryptUpdate = NULL;
static MD5_fn p_MD5 = NULL;

/* dbghelp.dll MiniDumpWriteDump function pointer */
typedef BOOL (WINAPI *MiniDumpWriteDump_fn)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    DWORD DumpType,
    PVOID ExceptionParam,
    PVOID UserStreamParam,
    PVOID CallbackParam
);

static MiniDumpWriteDump_fn p_MiniDumpWriteDump = NULL;

/**
 * Dynamically loads OpenSSL libcrypto library and resolves AES-256-CFB & MD5 functions.
 * Returns 1 on success, 0 on failure.
 */
static int load_crypto(void) {
    const char* dlls[] = {
        "libcrypto-3-x64.dll",
        "libcrypto.dll",
        "libcrypto-1_1-x64.dll"
    };

    HMODULE mod = NULL;
    for (int i = 0; i < 3; i++) {
        mod = LoadLibraryA(dlls[i]);
        if (mod) break;
    }

    if (!mod) {
        fprintf(stderr, "[-] Error: libcrypto not found in system or application directory.\n");
        fprintf(stderr, "    Please ensure libcrypto-3-x64.dll or libcrypto.dll is present.\n");
        return 0;
    }

    p_EVP_CIPHER_CTX_new = (EVP_CIPHER_CTX_new_fn)GetProcAddress(mod, "EVP_CIPHER_CTX_new");
    p_EVP_CIPHER_CTX_free = (EVP_CIPHER_CTX_free_fn)GetProcAddress(mod, "EVP_CIPHER_CTX_free");
    p_EVP_CIPHER_CTX_reset = (EVP_CIPHER_CTX_reset_fn)GetProcAddress(mod, "EVP_CIPHER_CTX_reset");
    p_EVP_aes_256_cfb128 = (EVP_aes_256_cfb128_fn)GetProcAddress(mod, "EVP_aes_256_cfb128");
    p_EVP_DecryptInit_ex = (EVP_DecryptInit_ex_fn)GetProcAddress(mod, "EVP_DecryptInit_ex");
    p_EVP_DecryptUpdate = (EVP_DecryptUpdate_fn)GetProcAddress(mod, "EVP_DecryptUpdate");
    p_MD5 = (MD5_fn)GetProcAddress(mod, "MD5");

    return (p_EVP_CIPHER_CTX_new && p_EVP_aes_256_cfb128 && p_MD5);
}

/**
 * Loads dbghelp.dll for automated Windows memory dumping.
 * Returns 1 on success, 0 on failure.
 */
static int load_dbghelp(void) {
    if (p_MiniDumpWriteDump) return 1;
    HMODULE mod = LoadLibraryA("dbghelp.dll");
    if (!mod) return 0;
    p_MiniDumpWriteDump = (MiniDumpWriteDump_fn)GetProcAddress(mod, "MiniDumpWriteDump");
    return (p_MiniDumpWriteDump != NULL);
}

/**
 * Parameters extracted from the Godot PCK header for key verification.
 */
typedef struct {
    unsigned char expected_md5[16];   /* Expected MD5 checksum of decrypted data */
    unsigned char test_iv[16];        /* Initialization vector (IV) from PCK */
    unsigned long long test_len;      /* Length of unpadded plaintext payload */
    size_t ds;                        /* Aligned block size (16-byte boundary) */
    unsigned char* test_cipher;       /* Ciphertext sample used for verification */
    int is_directory;                 /* 1 if directory index, 0 if encrypted file */
    unsigned int file_count;          /* File count in PCK */
    unsigned int format_version;      /* Godot PCK format version */
} CryptoParams;

/**
 * Displays command-line help and usage instructions.
 */
static void show_usage(const char* name) {
    printf("=================================================================\n");
    printf(" Godot Memory Dump AES-256 Key Finder v%s (Windows x64)\n", TOOL_VER);
    printf(" Author: adisc (https://github.com/adisc99)\n");
    printf("=================================================================\n\n");
    printf("Usage:\n");
    printf("  %s --auto <game.exe>\n", name);
    printf("      Launches the game, captures its process memory (RAM dump),\n");
    printf("      extracts the AES-256 encryption key, and cleans up.\n\n");
    printf("  %s <game.pck | game.exe> <dump.dmp | game.exe>\n", name);
    printf("      Scans an existing dump file or game binary against the PCK.\n\n");
    printf("Examples:\n");
    printf("  %s --auto Game.exe\n", name);
    printf("  %s data.pck memory.dmp\n", name);
    printf("  %s Game.exe Game.exe\n\n", name);
    printf("Note: This tool is designed natively for Windows x64 systems.\n");
}

/**
 * Parses Godot PCK header (standalone .pck, embedded in .exe, or PE section).
 * Populates CryptoParams with expected MD5, IV, and sample ciphertext.
 * Returns 1 on success, 0 on failure.
 */
static int read_pck_header(const char* pck_path, CryptoParams* out) {
    FILE* f = fopen(pck_path, "rb");
    if (!f) {
        fprintf(stderr, "[-] Error: Unable to open '%s'\n", pck_path);
        return 0;
    }

    _fseeki64(f, 0, SEEK_END);
    long long file_size = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);

    unsigned int magic = 0;
    if (fread(&magic, 4, 1, f) != 1) {
        fclose(f);
        return 0;
    }

    long long pck_offset = 0;
    int found_pck = 0;

    /* 1. Direct standalone PCK check ('GDPC' = 0x43504447) */
    if (magic == 0x43504447) {
        found_pck = 1;
        pck_offset = 0;
    }

    /* 2. Check PE Section "pck" inside Windows executable */
    if (!found_pck && file_size > 0x1000) {
        _fseeki64(f, 0x3C, SEEK_SET);
        unsigned int pe_pos = 0;
        if (fread(&pe_pos, 4, 1, f) == 1 && pe_pos < file_size - 0x100) {
            _fseeki64(f, pe_pos, SEEK_SET);
            char pe_sig[4];
            if (fread(pe_sig, 1, 4, f) == 4 && memcmp(pe_sig, "PE\0\0", 4) == 0) {
                unsigned short num_sec = 0;
                _fseeki64(f, pe_pos + 6, SEEK_SET);
                fread(&num_sec, 2, 1, f);
                unsigned short opt_sz = 0;
                _fseeki64(f, pe_pos + 20, SEEK_SET);
                fread(&opt_sz, 2, 1, f);
                long long sec_table = pe_pos + 24 + opt_sz;
                for (int s = 0; s < num_sec; s++) {
                    _fseeki64(f, sec_table + s * 40, SEEK_SET);
                    char s_name[8];
                    fread(s_name, 1, 8, f);
                    if (_strnicmp(s_name, "pck", 3) == 0) {
                        _fseeki64(f, sec_table + s * 40 + 20, SEEK_SET);
                        unsigned int raw_ptr = 0;
                        fread(&raw_ptr, 4, 1, f);
                        _fseeki64(f, raw_ptr, SEEK_SET);
                        unsigned int smagic = 0;
                        fread(&smagic, 4, 1, f);
                        if (smagic == 0x43504447) {
                            found_pck = 1;
                            pck_offset = raw_ptr;
                            break;
                        }
                    }
                }
            }
        }
    }

    /* 3. Check Godot embedded footer at end of file */
    if (!found_pck && file_size > 16) {
        _fseeki64(f, file_size - 4, SEEK_SET);
        unsigned int footer_magic = 0;
        fread(&footer_magic, 4, 1, f);
        if (footer_magic == 0x43504447) {
            _fseeki64(f, file_size - 12, SEEK_SET);
            unsigned long long emb_off = 0;
            fread(&emb_off, 8, 1, f);
            if (emb_off < (unsigned long long)file_size) {
                _fseeki64(f, emb_off, SEEK_SET);
                unsigned int smagic = 0;
                fread(&smagic, 4, 1, f);
                if (smagic == 0x43504447) {
                    found_pck = 1;
                    pck_offset = emb_off;
                }
            }
        }
    }

    if (!found_pck) {
        fprintf(stderr, "[-] Error: Valid Godot PCK header ('GDPC') not found.\n");
        fclose(f);
        return 0;
    }

    _fseeki64(f, pck_offset + 4, SEEK_SET);
    fread(&out->format_version, 4, 1, f);
    unsigned int eng_maj = 0, eng_min = 0, eng_patch = 0;
    fread(&eng_maj, 4, 1, f);
    fread(&eng_min, 4, 1, f);
    fread(&eng_patch, 4, 1, f);

    unsigned int flags = 0;
    if (out->format_version >= 2) {
        fread(&flags, 4, 1, f);
    }

    unsigned long long file_base = 0;
    if (out->format_version >= 2) {
        fread(&file_base, 8, 1, f);
    }

    long long dir_offset = 0;
    if (out->format_version >= 3) {
        fread(&dir_offset, 8, 1, f);
        _fseeki64(f, 56, SEEK_CUR);
    } else {
        _fseeki64(f, 64, SEEK_CUR);
        dir_offset = _ftelli64(f) - pck_offset;
    }

    int is_dir_encrypted = (flags & 1) != 0;
    if (is_dir_encrypted) {
        /* Directory table itself is encrypted with AES-256 (PACK_DIR_ENCRYPTED) */
        _fseeki64(f, pck_offset + dir_offset, SEEK_SET);
        fread(&out->file_count, 4, 1, f);
        fread(out->expected_md5, 1, 16, f);
        fread(&out->test_len, 8, 1, f);
        fread(out->test_iv, 1, 16, f);

        out->ds = out->test_len + (out->test_len % 16 ? (16 - out->test_len % 16) : 0);
        out->test_cipher = (unsigned char*)malloc(out->ds);
        if (!out->test_cipher) {
            fclose(f);
            return 0;
        }
        fread(out->test_cipher, 1, out->ds, f);
        out->is_directory = 1;
        fclose(f);
        return 1;
    }

    /* Unencrypted directory: search for the first encrypted resource file */
    _fseeki64(f, pck_offset + dir_offset, SEEK_SET);
    fread(&out->file_count, 4, 1, f);

    for (unsigned int i = 0; i < out->file_count; i++) {
        unsigned int path_len = 0;
        fread(&path_len, 4, 1, f);
        _fseeki64(f, path_len, SEEK_CUR);

        unsigned long long file_offset = 0;
        unsigned long long file_sz = 0;
        unsigned char file_md5[16];
        unsigned int file_flags = 0;

        fread(&file_offset, 8, 1, f);
        fread(&file_sz, 8, 1, f);
        fread(file_md5, 1, 16, f);
        if (out->format_version >= 2) {
            fread(&file_flags, 4, 1, f);
        }

        if ((file_flags & 1) && file_sz > 32) {
            _fseeki64(f, pck_offset + file_base + file_offset, SEEK_SET);
            fread(out->expected_md5, 1, 16, f);
            fread(&out->test_len, 8, 1, f);
            fread(out->test_iv, 1, 16, f);

            out->ds = out->test_len + (out->test_len % 16 ? (16 - out->test_len % 16) : 0);
            out->test_cipher = (unsigned char*)malloc(out->ds);
            if (!out->test_cipher) {
                fclose(f);
                return 0;
            }
            fread(out->test_cipher, 1, out->ds, f);
            out->is_directory = 0;
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    fprintf(stderr, "[-] No encrypted data found in PCK archive.\n");
    return 0;
}

/**
 * Finds matching PCK package companion file or uses embedded executable.
 */
static int locate_pck(const char* exe_path, char* out_pck, size_t max_len) {
    strncpy(out_pck, exe_path, max_len - 1);
    char* dot = strrchr(out_pck, '.');
    if (dot && (_stricmp(dot, ".exe") == 0)) {
        strcpy(dot, ".pck");
        if (GetFileAttributesA(out_pck) != INVALID_FILE_ATTRIBUTES) return 1;
    }

    char dir[MAX_PATH];
    strncpy(dir, exe_path, sizeof(dir) - 1);
    char* slash = strrchr(dir, '\\');
    if (!slash) slash = strrchr(dir, '/');
    if (slash) {
        *(slash + 1) = '\0';
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s*.pck", dir);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            snprintf(out_pck, max_len, "%s%s", dir, fd.cFileName);
            FindClose(hFind);
            return 1;
        }
    }

    /* Fallback: Embedded PCK directly inside the .exe */
    strncpy(out_pck, exe_path, max_len - 1);
    return 1;
}

/**
 * Automatically launches game process, waits for Godot engine initialization,
 * captures a full memory minidump via Windows dbghelp.dll, and terminates the game.
 * Returns 1 on success, 0 on failure.
 */
static int grab_ram_dump(const char* exe_path, char* dump_out, size_t max_len) {
    if (!load_dbghelp()) return 0;

    char dir[MAX_PATH] = {0};
    strncpy(dir, exe_path, sizeof(dir) - 1);
    char* slash = strrchr(dir, '\\');
    if (!slash) slash = strrchr(dir, '/');
    if (slash) *slash = '\0'; else strcpy(dir, ".");

    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(dump_out, max_len, "%sgodot_mem_%u.dmp", tmp, (unsigned int)time(NULL));

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmd[MAX_PATH * 2];
    snprintf(cmd, sizeof(cmd), "\"%s\"", exe_path);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
        fprintf(stderr, "[-] Failed to start game process (error code: %lu)\n", GetLastError());
        return 0;
    }

    printf("[*] Process started (PID: %lu). Waiting for Godot initialization...", pi.dwProcessId);
    fflush(stdout);
    Sleep(2200);

    HANDLE hFile = CreateFileA(dump_out, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    int ok = 0;
    if (hFile != INVALID_HANDLE_VALUE) {
        /* MiniDumpWithFullMemory = 0x00000002 */
        ok = p_MiniDumpWriteDump(pi.hProcess, pi.dwProcessId, hFile, 0x00000002, NULL, NULL, NULL);
        CloseHandle(hFile);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!ok) {
        printf(" failed.\n");
        DeleteFileA(dump_out);
        return 0;
    }

    printf(" done.\n");
    return 1;
}

/**
 * High-performance sliding window multi-threaded AES-256-CFB scanner.
 * Uses OpenMP to scan millions of candidate 32-byte blocks per second.
 * Employs fast early-exit heuristics (checking the first 16 bytes) before full MD5 verification.
 */
static int run_scan(const unsigned char* data, long long size, const CryptoParams* target, unsigned char* out_key) {
    volatile int found = 0;
    void* algo = p_EVP_aes_256_cfb128();
    unsigned char c0[16];
    memcpy(c0, target->test_cipher, 16);

    double t0 = omp_get_wtime();
    long long total = size - 32;

#pragma omp parallel
    {
        void* ctx = p_EVP_CIPHER_CTX_new();
        unsigned char p0[16];
        int out_len = 0;
        unsigned char* dec = (unsigned char*)malloc(target->ds);

#pragma omp for schedule(dynamic, 65536)
        for (long long i = 0; i < total; i++) {
            if (found) continue;

            const unsigned char* cand = data + i;

            /* Filter out uniform or null regions */
            if (cand[0] == 0 && cand[1] == 0 && cand[2] == 0 && cand[3] == 0) continue;
            if (cand[0] == 0xFF && cand[1] == 0xFF && cand[2] == 0xFF && cand[3] == 0xFF) continue;

            /* Trial decrypt of the first 16 bytes */
            if (p_EVP_CIPHER_CTX_reset) p_EVP_CIPHER_CTX_reset(ctx);
            p_EVP_DecryptInit_ex(ctx, algo, NULL, cand, target->test_iv);
            p_EVP_DecryptUpdate(ctx, p0, &out_len, c0, 16);

            int match = 0;
            if (target->is_directory) {
                /* Heuristic: directory entry paths typically begin with 'res://' or 4-byte length + ASCII */
                if (p0[2] == 0 && p0[3] == 0 && p0[1] <= 4 && (p0[0] != 0 || p0[1] != 0)) {
                    if (p0[4] >= 32 && p0[4] <= 126 && p0[5] >= 32 && p0[5] <= 126) match = 1;
                } else if (memcmp(p0, "res://", 6) == 0) {
                    match = 1;
                }
            } else {
                /* Heuristic: Godot file headers (RSRC, GDSC, PNG, RIFF, ASCII) */
                if (memcmp(p0, "RSRC", 4) == 0 || memcmp(p0, "GDSC", 4) == 0 ||
                    memcmp(p0, "\x89PNG", 4) == 0 || memcmp(p0, "RIFF", 4) == 0 ||
                    (p0[0] >= 32 && p0[1] >= 32 && p0[2] >= 32 && p0[3] >= 32)) {
                    match = 1;
                }
            }

            /* Full MD5 verification on heuristic match */
            if (match) {
                if (p_EVP_CIPHER_CTX_reset) p_EVP_CIPHER_CTX_reset(ctx);
                p_EVP_DecryptInit_ex(ctx, algo, NULL, cand, target->test_iv);
                p_EVP_DecryptUpdate(ctx, dec, &out_len, target->test_cipher, (int)target->ds);

                unsigned char dig[16];
                p_MD5(dec, target->test_len, dig);

                if (memcmp(dig, target->expected_md5, 16) == 0) {
#pragma omp critical
                    {
                        if (!found) {
                            found = 1;
                            memcpy(out_key, cand, 32);
                        }
                    }
                }
            }
        }

        free(dec);
        p_EVP_CIPHER_CTX_free(ctx);
    }

    double t1 = omp_get_wtime();
    printf("[*] Scan completed in %.2f seconds using %d threads.\n", t1 - t0, omp_get_max_threads());
    return found;
}

int main(int argc, char* argv[]) {
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        show_usage(argv[0]);
        return (argc < 2) ? 1 : 0;
    }

    int auto_mode = 0;
    const char* exe_file = NULL;
    char pck_path[MAX_PATH] = {0};
    char target_path[MAX_PATH] = {0};
    int cleanup = 0;

    if (strcmp(argv[1], "--auto") == 0 || strcmp(argv[1], "-a") == 0) {
        if (argc < 3) {
            show_usage(argv[0]);
            return 1;
        }
        auto_mode = 1;
        exe_file = argv[2];
        locate_pck(exe_file, pck_path, sizeof(pck_path));
    } else {
        if (argc == 2 && (strstr(argv[1], ".exe") || strstr(argv[1], ".EXE"))) {
            auto_mode = 1;
            exe_file = argv[1];
            locate_pck(exe_file, pck_path, sizeof(pck_path));
        } else if (argc >= 3) {
            strncpy(pck_path, argv[1], sizeof(pck_path) - 1);
            strncpy(target_path, argv[2], sizeof(target_path) - 1);
        } else {
            show_usage(argv[0]);
            return 1;
        }
    }

    if (!load_crypto()) return 1;

    if (auto_mode) {
        if (!grab_ram_dump(exe_file, target_path, sizeof(target_path))) return 1;
        cleanup = 1;
    }

    CryptoParams target;
    memset(&target, 0, sizeof(target));
    if (!read_pck_header(pck_path, &target)) {
        if (cleanup) DeleteFileA(target_path);
        return 1;
    }

    FILE* fp = fopen(target_path, "rb");
    if (!fp) {
        fprintf(stderr, "[-] Error: Unable to open target scan file '%s'\n", target_path);
        free(target.test_cipher);
        if (cleanup) DeleteFileA(target_path);
        return 1;
    }

    _fseeki64(fp, 0, SEEK_END);
    long long sz = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);

    unsigned char* buf = (unsigned char*)malloc(sz);
    if (!buf) {
        fprintf(stderr, "[-] Error: Memory allocation failed (%lld bytes)\n", sz);
        fclose(fp);
        free(target.test_cipher);
        if (cleanup) DeleteFileA(target_path);
        return 1;
    }

    fread(buf, 1, sz, fp);
    fclose(fp);

    unsigned char key[32];
    memset(key, 0, sizeof(key));

    printf("[*] Scanning %lld MB for 256-bit AES key...\n", sz / (1024 * 1024));
    int ok = run_scan(buf, sz, &target, key);

    free(buf);
    free(target.test_cipher);
    if (cleanup) DeleteFileA(target_path);

    if (ok) {
        printf("\n=================================================================\n");
        printf(" [+] AES-256 Key Found!\n");
        printf("     Hex: ");
        for (int i = 0; i < 32; i++) printf("%02x", key[i]);
        printf("\n=================================================================\n\n");
        return 0;
    }

    printf("\n[-] AES-256 Key not found in target file.\n");
    return 2;
}
