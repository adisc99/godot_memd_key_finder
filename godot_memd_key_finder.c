#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <omp.h>
#include <time.h>

#define TOOL_VER "2.1"

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

static int load_dbghelp(void) {
    if (p_MiniDumpWriteDump) return 1;
    HMODULE mod = LoadLibraryA("dbghelp.dll");
    if (!mod) return 0;
    p_MiniDumpWriteDump = (MiniDumpWriteDump_fn)GetProcAddress(mod, "MiniDumpWriteDump");
    return (p_MiniDumpWriteDump != NULL);
}

typedef struct {
    unsigned char expected_md5[16];
    unsigned char test_iv[16];
    unsigned long long test_len;
    size_t ds;
    unsigned char* test_cipher;
    int is_directory;
    unsigned int file_count;
    unsigned int format_version;
} CryptoParams;

static void show_usage(const char* name) {
    printf("=================================================================\n");
    printf(" Godot Memory Dump & Extraction Key Finder v%s (Windows x64)\n", TOOL_VER);
    printf(" Author: adisc (https://github.com/adisc99)\n");
    printf("=================================================================\n\n");
    printf("Usage:\n");
    printf("  %s --hook <game.exe>\n", name);
    printf("      [Recommended] Launches game under lightweight native debugger,\n");
    printf("      hooks Godot's open_and_parse() and intercepts AES-256 key live!\n\n");
    printf("  %s --auto <game.exe> [delay_seconds]\n", name);
    printf("      Launches game, captures full RAM dump, scans for AES-256 key.\n\n");
    printf("  %s --dump-files <dump.dmp | game.exe> [output.tar]\n", name);
    printf("      Extracts all game resource files, scripts & scenes into a TAR package\n");
    printf("      for modding and translations.\n\n");
    printf("  %s <game.pck | game.exe> <dump.dmp | game.exe>\n", name);
    printf("      Scans an existing dump file or game binary against the PCK.\n\n");
    printf("Examples:\n");
    printf("  %s --hook Game.exe\n", name);
    printf("  %s --dump-files Game.dmp game_resources.tar\n", name);
    printf("  %s --auto Game.exe 6\n", name);
    printf("  %s data.pck memory.dmp\n\n", name);
}

/* POSIX ustar header (512 bytes) */
typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
} TarHeader;

static void tar_write_header(FILE* fp, const char* filename, size_t file_size) {
    TarHeader h;
    memset(&h, 0, sizeof(h));

    strncpy(h.name, filename, sizeof(h.name) - 1);
    snprintf(h.mode, sizeof(h.mode), "%07o", 0644);
    snprintf(h.uid, sizeof(h.uid), "%07o", 0);
    snprintf(h.gid, sizeof(h.gid), "%07o", 0);
    snprintf(h.size, sizeof(h.size), "%011llo", (unsigned long long)file_size);
    snprintf(h.mtime, sizeof(h.mtime), "%011lo", (unsigned long)time(NULL));
    memcpy(h.magic, "ustar ", 6);
    memcpy(h.version, " \0", 2);
    h.typeflag = '0';

    memset(h.chksum, ' ', 8);
    unsigned int sum = 0;
    const unsigned char* raw = (const unsigned char*)&h;
    for (size_t i = 0; i < sizeof(TarHeader); i++) {
        sum += raw[i];
    }
    snprintf(h.chksum, sizeof(h.chksum), "%06o", sum);
    h.chksum[6] = '\0';
    h.chksum[7] = ' ';

    fwrite(&h, 1, sizeof(h), fp);
}

static void tar_pad(FILE* fp, size_t file_size) {
    size_t rem = file_size % 512;
    if (rem != 0) {
        size_t pad_len = 512 - rem;
        char zero[512] = {0};
        fwrite(zero, 1, pad_len, fp);
    }
}

/**
 * Extracts resources from memory dump into a standard TAR archive.
 */
static int dump_files_to_tar(const char* dmp_path, const char* out_tar_path) {
    FILE* f = fopen(dmp_path, "rb");
    if (!f) {
        fprintf(stderr, "[-] Error: Unable to open dump file '%s'\n", dmp_path);
        return 0;
    }

    _fseeki64(f, 0, SEEK_END);
    long long sz = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);

    printf("[*] Scanning memory dump (%lld MB) for extractable resources...\n", sz / (1024 * 1024));

    FILE* tar_out = fopen(out_tar_path, "wb");
    if (!tar_out) {
        fprintf(stderr, "[-] Error: Unable to create output TAR file '%s'\n", out_tar_path);
        fclose(f);
        return 0;
    }

    /* Track extracted paths to avoid duplicates */
    #define MAX_PATHS 16384
    char** seen_paths = (char**)malloc(MAX_PATHS * sizeof(char*));
    int seen_count = 0;

    long long block_sz = 64 * 1024 * 1024;
    unsigned char* chunk = (unsigned char*)malloc(block_sz + 4096);
    if (!chunk) {
        fclose(f);
        fclose(tar_out);
        free(seen_paths);
        return 0;
    }

    int files_extracted = 0;

    for (long long off = 0; off < sz; off += block_sz) {
        _fseeki64(f, off, SEEK_SET);
        size_t read_bytes = fread(chunk, 1, block_sz + 4096, f);
        if (read_bytes < 32) break;

        for (size_t i = 0; i < read_bytes - 32; i++) {
            /* Find 'res://' */
            if (chunk[i] == 'r' && chunk[i+1] == 'e' && chunk[i+2] == 's' &&
                chunk[i+3] == ':' && chunk[i+4] == '/' && chunk[i+5] == '/') {

                char path[512] = {0};
                size_t pidx = 0;
                while (i + pidx < read_bytes && pidx < 255) {
                    char c = (char)chunk[i + pidx];
                    if (c == '\0' || c == '"' || c == '\n' || c == '\r' || c == ' ' || c < 32 || c > 126) break;
                    path[pidx++] = c;
                }
                path[pidx] = '\0';

                /* Check for valid extension */
                char* dot = strrchr(path, '.');
                if (!dot || (dot - path) < 8 || strlen(dot) < 2 || strlen(dot) > 10) continue;

                /* Deduplicate */
                int dup = 0;
                for (int s = 0; s < seen_count; s++) {
                    if (strcmp(seen_paths[s], path) == 0) {
                        dup = 1;
                        break;
                    }
                }
                if (dup) continue;

                if (seen_count < MAX_PATHS) {
                    seen_paths[seen_count++] = _strdup(path);
                }

                /* Check for inline CowData payload or metadata */
                size_t payload_len = 0;
                const unsigned char* payload_data = NULL;

                /* If preceded by 64-bit CowData length: [i - 16] or [i - 32] */
                if (i >= 16) {
                    unsigned long long clen = *(unsigned long long*)(chunk + i - 16);
                    if (clen > 0 && clen <= 10000000) {
                        /* Check if valid resource follows path */
                        size_t after_path = i + pidx + 1;
                        while (after_path < read_bytes && chunk[after_path] == 0) after_path++;
                        if (after_path + 4 < read_bytes) {
                            if (memcmp(chunk + after_path, "GDSC", 4) == 0 ||
                                memcmp(chunk + after_path, "GDCX", 4) == 0 ||
                                memcmp(chunk + after_path, "RSRC", 4) == 0 ||
                                memcmp(chunk + after_path, "\x89PNG", 4) == 0) {
                                payload_data = chunk + after_path;
                                payload_len = clen;
                            }
                        }
                    }
                }

                /* If no inline binary payload, store path text entry */
                char tar_name[512];
                if (strncmp(path, "res://", 6) == 0) {
                    snprintf(tar_name, sizeof(tar_name), "%s", path + 6);
                } else {
                    snprintf(tar_name, sizeof(tar_name), "%s", path);
                }

                if (payload_data && payload_len > 0 && payload_len < 50000000) {
                    tar_write_header(tar_out, tar_name, payload_len);
                    fwrite(payload_data, 1, payload_len, tar_out);
                    tar_pad(tar_out, payload_len);
                } else {
                    /* Create entry with path reference */
                    char placeholder[256];
                    int plen = snprintf(placeholder, sizeof(placeholder), "Godot Resource: %s\n", path);
                    tar_write_header(tar_out, tar_name, plen);
                    fwrite(placeholder, 1, plen, tar_out);
                    tar_pad(tar_out, plen);
                }

                files_extracted++;
                if (files_extracted % 250 == 0) {
                    printf("[*] Extracted %d resources to TAR...\r", files_extracted);
                    fflush(stdout);
                }
            }
        }
    }

    /* Write 1024 zero bytes (TAR end-of-archive marker) */
    char end_marker[1024] = {0};
    fwrite(end_marker, 1, sizeof(end_marker), tar_out);

    fclose(f);
    fclose(tar_out);
    free(chunk);

    for (int s = 0; s < seen_count; s++) {
        free(seen_paths[s]);
    }
    free(seen_paths);

    printf("\n[+] Extraction complete! Successfully packed %d resources into:\n    %s\n", files_extracted, out_tar_path);
    return files_extracted;
}

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

    if (magic == 0x43504447) {
        found_pck = 1;
        pck_offset = 0;
    }

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

    strncpy(out_pck, exe_path, max_len - 1);
    return 1;
}

static int verify_aes_key(const unsigned char* key, const CryptoParams* target) {
    void* ctx = p_EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    void* algo = p_EVP_aes_256_cfb128();

    unsigned char* dec = (unsigned char*)malloc(target->ds);
    if (!dec) {
        p_EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int out_len = 0;
    if (p_EVP_CIPHER_CTX_reset) p_EVP_CIPHER_CTX_reset(ctx);
    p_EVP_DecryptInit_ex(ctx, algo, NULL, key, target->test_iv);
    p_EVP_DecryptUpdate(ctx, dec, &out_len, target->test_cipher, (int)target->ds);

    unsigned char dig[16];
    p_MD5(dec, target->test_len, dig);

    int ok = (memcmp(dig, target->expected_md5, 16) == 0);

    free(dec);
    p_EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static unsigned long long find_open_and_parse_rva(const char* exe_path) {
    FILE* fp = fopen(exe_path, "rb");
    if (!fp) return 0;

    _fseeki64(fp, 0, SEEK_END);
    long long sz = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);

    unsigned char* data = (unsigned char*)malloc(sz);
    if (!data) {
        fclose(fp);
        return 0;
    }

    fread(data, 1, sz, fp);
    fclose(fp);

    const unsigned char pat[] = { 0x49, 0x8b, 0x40, 0x08, 0x48, 0x85, 0xc0 };
    const unsigned char check_sz[] = { 0x48, 0x83, 0x78, 0xf0, 0x20 };

    unsigned long long rva = 0;
    for (long long i = 0x400; i < sz - 40; i++) {
        if (memcmp(data + i, pat, sizeof(pat)) == 0) {
            for (int k = 0; k < 25; k++) {
                if (memcmp(data + i + k, check_sz, sizeof(check_sz)) == 0) {
                    long long func_file_off = i - 57;
                    rva = (func_file_off - 0x400) + 0x1000;
                    break;
                }
            }
            if (rva) break;
        }
    }

    free(data);
    return rva;
}

static int run_hook(const char* exe_path, const CryptoParams* target, unsigned char* out_key) {
    unsigned long long func_rva = find_open_and_parse_rva(exe_path);
    if (!func_rva) {
        fprintf(stderr, "[-] Warning: open_and_parse() signature not found in executable.\n");
        return 0;
    }

    printf("[*] Detected open_and_parse() at RVA: 0x%llX\n", func_rva);

    char dir[MAX_PATH] = {0};
    strncpy(dir, exe_path, sizeof(dir) - 1);
    char* slash = strrchr(dir, '\\');
    if (!slash) slash = strrchr(dir, '/');
    if (slash) *slash = '\0'; else strcpy(dir, ".");

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    char cmd[MAX_PATH * 2];
    snprintf(cmd, sizeof(cmd), "\"%s\"", exe_path);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, dir, &si, &pi)) {
        fprintf(stderr, "[-] Failed to launch game in debug mode (Error: %lu)\n", GetLastError());
        return 0;
    }

    printf("[*] Debug session started (PID: %lu). Waiting for Godot decryption hook...", pi.dwProcessId);
    fflush(stdout);

    DEBUG_EVENT de;
    unsigned long long image_base = 0;
    unsigned long long bp_addr = 0;
    unsigned char orig_byte = 0;
    int bp_set = 0;
    int key_found = 0;

    while (WaitForDebugEvent(&de, 15000)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            image_base = (unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
            bp_addr = image_base + func_rva;

            ReadProcessMemory(pi.hProcess, (LPCVOID)bp_addr, &orig_byte, 1, NULL);

            unsigned char int3 = 0xCC;
            WriteProcessMemory(pi.hProcess, (LPVOID)bp_addr, &int3, 1, NULL);
            FlushInstructionCache(pi.hProcess, (LPCVOID)bp_addr, 1);
            bp_set = 1;
        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                unsigned long long ex_addr = (unsigned long long)de.u.Exception.ExceptionRecord.ExceptionAddress;
                if (bp_set && ex_addr == bp_addr) {
                    WriteProcessMemory(pi.hProcess, (LPVOID)bp_addr, &orig_byte, 1, NULL);
                    FlushInstructionCache(pi.hProcess, (LPCVOID)bp_addr, 1);

                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                    if (hThread) {
                        CONTEXT ctx;
                        memset(&ctx, 0, sizeof(ctx));
                        ctx.ContextFlags = CONTEXT_ALL;
                        if (GetThreadContext(hThread, &ctx)) {
                            ctx.Rip = bp_addr;

                            unsigned char r8_mem[64];
                            memset(r8_mem, 0, sizeof(r8_mem));
                            ReadProcessMemory(pi.hProcess, (LPCVOID)ctx.R8, r8_mem, 64, NULL);

                            unsigned long long candidate_ptrs[8] = {
                                ctx.R8,
                                *(unsigned long long*)(r8_mem + 0),
                                *(unsigned long long*)(r8_mem + 8),
                                *(unsigned long long*)(r8_mem + 16),
                                *(unsigned long long*)(r8_mem + 24),
                                ctx.Rdx,
                                ctx.Rcx,
                                0
                            };

                            for (int p = 0; p < 7 && !key_found; p++) {
                                unsigned long long paddr = candidate_ptrs[p];
                                if (paddr > 0x10000 && paddr < 0x7FFFFFFFFFFFULL) {
                                    unsigned char kcand[32];
                                    if (ReadProcessMemory(pi.hProcess, (LPCVOID)paddr, kcand, 32, NULL)) {
                                        if (verify_aes_key(kcand, target)) {
                                            memcpy(out_key, kcand, 32);
                                            key_found = 1;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (key_found) {
                                printf(" hooked & verified!\n");
                                SetThreadContext(hThread, &ctx);
                                CloseHandle(hThread);
                                ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                                break;
                            } else {
                                ctx.EFlags |= 0x100;
                                SetThreadContext(hThread, &ctx);
                            }
                        }
                        CloseHandle(hThread);
                    }

                    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                    continue;
                }
            } else if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                unsigned char int3 = 0xCC;
                WriteProcessMemory(pi.hProcess, (LPVOID)bp_addr, &int3, 1, NULL);
                FlushInstructionCache(pi.hProcess, (LPCVOID)bp_addr, 1);
                ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                continue;
            }
        }

        ContinueDebugEvent(de.dwProcessId,
                           de.dwThreadId,
                           de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                           de.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT &&
                           de.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return key_found;
}

static int grab_ram_dump(const char* exe_path, char* dump_out, size_t max_len, int delay_sec) {
    if (delay_sec <= 0) delay_sec = 4;
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
    si.wShowWindow = SW_SHOWNORMAL;

    char cmd[MAX_PATH * 2];
    snprintf(cmd, sizeof(cmd), "\"%s\"", exe_path);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
        fprintf(stderr, "[-] Failed to start game process (error code: %lu)\n", GetLastError());
        return 0;
    }

    printf("[*] Process started (PID: %lu). Waiting %d seconds for Godot initialization...", pi.dwProcessId, delay_sec);
    fflush(stdout);
    Sleep(delay_sec * 1000);

    HANDLE hFile = CreateFileA(dump_out, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    int ok = 0;
    if (hFile != INVALID_HANDLE_VALUE) {
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

            if (cand[0] == 0 && cand[1] == 0 && cand[2] == 0 && cand[3] == 0) continue;
            if (cand[0] == 0xFF && cand[1] == 0xFF && cand[2] == 0xFF && cand[3] == 0xFF) continue;

            if (p_EVP_CIPHER_CTX_reset) p_EVP_CIPHER_CTX_reset(ctx);
            p_EVP_DecryptInit_ex(ctx, algo, NULL, cand, target->test_iv);
            p_EVP_DecryptUpdate(ctx, p0, &out_len, c0, 16);

            int match = 0;
            if (target->is_directory) {
                unsigned int plen = (unsigned int)p0[0] | ((unsigned int)p0[1] << 8);
                if (p0[2] == 0 && p0[3] == 0 && plen >= 1 && plen <= 1024) {
                    if (p0[4] >= 32 && p0[4] <= 126) match = 1;
                } else if (memcmp(p0, "res://", 6) == 0) {
                    match = 1;
                }
            } else {
                if (memcmp(p0, "RSRC", 4) == 0 || memcmp(p0, "GDSC", 4) == 0 ||
                    memcmp(p0, "\x89PNG", 4) == 0 || memcmp(p0, "RIFF", 4) == 0 ||
                    (p0[0] >= 32 && p0[1] >= 32 && p0[2] >= 32 && p0[3] >= 32)) {
                    match = 1;
                }
            }

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

    int hook_mode = 0;
    int auto_mode = 0;
    int dump_files_mode = 0;
    int delay_sec = 4;
    const char* exe_file = NULL;
    char pck_path[MAX_PATH] = {0};
    char target_path[MAX_PATH] = {0};
    char out_tar_path[MAX_PATH] = {0};
    int cleanup = 0;

    if (strcmp(argv[1], "--dump-files") == 0) {
        if (argc < 3) {
            show_usage(argv[0]);
            return 1;
        }
        dump_files_mode = 1;
        const char* input_arg = argv[2];
        if (argc >= 4) {
            strncpy(out_tar_path, argv[3], sizeof(out_tar_path) - 1);
        } else {
            snprintf(out_tar_path, sizeof(out_tar_path), "game_resources.tar");
        }

        if (strstr(input_arg, ".dmp") || strstr(input_arg, ".DMP")) {
            strncpy(target_path, input_arg, sizeof(target_path) - 1);
        } else {
            exe_file = input_arg;
            if (!grab_ram_dump(exe_file, target_path, sizeof(target_path), delay_sec)) {
                return 1;
            }
            cleanup = 1;
        }

        int extracted = dump_files_to_tar(target_path, out_tar_path);
        if (cleanup) DeleteFileA(target_path);
        return (extracted > 0) ? 0 : 1;
    }

    if (strcmp(argv[1], "--hook") == 0) {
        if (argc < 3) {
            show_usage(argv[0]);
            return 1;
        }
        hook_mode = 1;
        exe_file = argv[2];
        locate_pck(exe_file, pck_path, sizeof(pck_path));
    } else if (strcmp(argv[1], "--auto") == 0 || strcmp(argv[1], "-a") == 0) {
        if (argc < 3) {
            show_usage(argv[0]);
            return 1;
        }
        auto_mode = 1;
        exe_file = argv[2];
        if (argc >= 4) delay_sec = atoi(argv[3]);
        locate_pck(exe_file, pck_path, sizeof(pck_path));
    } else {
        if (argc >= 2 && (strstr(argv[1], ".exe") || strstr(argv[1], ".EXE")) && (argc == 2 || (argc == 3 && atoi(argv[2]) > 0))) {
            hook_mode = 1;
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

    CryptoParams target;
    memset(&target, 0, sizeof(target));
    if (!read_pck_header(pck_path, &target)) {
        return 1;
    }

    printf("[*] Target PCK: Format v%u, Type: %s, Expected MD5: ",
           target.format_version,
           target.is_directory ? "PACK_DIR_ENCRYPTED" : "Encrypted Resource");
    for (int i = 0; i < 16; i++) printf("%02x", target.expected_md5[i]);
    printf("\n");

    unsigned char key[32];
    memset(key, 0, sizeof(key));

    if (hook_mode) {
        int ok = run_hook(exe_file, &target, key);
        free(target.test_cipher);
        if (ok) {
            printf("\n=================================================================\n");
            printf(" [+] AES-256 Key Intercepted via Live Hook!\n");
            printf("     Hex: ");
            for (int i = 0; i < 32; i++) printf("%02x", key[i]);
            printf("\n=================================================================\n\n");
            return 0;
        }
        printf("\n[-] Hook completed but key could not be captured. Falling back to RAM scan...\n");
        auto_mode = 1;
    }

    if (auto_mode) {
        if (!grab_ram_dump(exe_file, target_path, sizeof(target_path), delay_sec)) {
            free(target.test_cipher);
            return 1;
        }
        cleanup = 1;
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
