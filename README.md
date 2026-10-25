# Godot Memory Dump & Extraction Key Finder (`godot_memd_key_finder`)

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)](https://github.com/adisc99/godot_memd_key_finder)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)](godot_memd_key_finder.c)

A high-performance, multi-threaded C tool designed to recover **AES-256 encryption keys** and **extract mounted resources** from **Godot Engine** games using live breakpoint hooking, runtime memory dumps (RAM), or static binary analysis.

Developed by [adisc](https://github.com/adisc99).

---

> [!IMPORTANT]
> **Windows-Only Tool**: This program relies on native Windows APIs (`CreateProcessA`, `MiniDumpWriteDump`, `dbghelp.dll`, Win32 Debug API) to launch processes, hook execution, and capture memory dumps on the fly. It is designed and compiled specifically for **Windows x64**.

---

## 🎯 Features

- **Live Decryption Hooking (`--hook`)**:
  - Automatically identifies Godot's internal `FileAccessEncrypted::open_and_parse()` routine via pattern scanning.
  - Launches the process under lightweight native Win32 debugging and sets an execution breakpoint (`INT 3`).
  - Intercepts CPU registers (`R8` / key pointer) and memory at the exact microsecond of decryption before the key can be zeroized (`memzero`) in RAM.
  - Automatic trap flag single-stepping (`TF`) to trace multi-call unpack sequences.
- **Full Resource Extraction to TAR (`--dump-files`)**:
  - Extracts all mounted resources, scripts (`.gd`, `.gdc`), scenes (`.tscn`, `.scn`), and metadata (`.tres`) directly from runtime memory.
  - Built-in zero-dependency POSIX ustar TAR writer: exports directly to `.tar` with full directory trees preserved.
  - Ideal for games where package directories are encrypted or keys are non-static, allowing immediate access for modding and translations.
- **Automated Memory Dumping (`--auto`)**:
  - Launches the target game with proper display context to avoid graphics driver stalls.
  - Configurable initialization timeout (`[delay_seconds]`).
  - Captures full process memory dump (`MiniDumpWithFullMemory` via `dbghelp.dll`).
  - Scans RAM for the 256-bit AES key and safely cleans up temporary dump files.
- **Support for All Godot PCK Versions**:
  - Godot 3.x and 4.x PCK archives (Format v1, v2, v3, and v4).
  - Encrypted Pack Directories (`PACK_DIR_ENCRYPTED`).
  - Individually encrypted internal resources.
  - Standalone `.pck` files and embedded executables (PE sections or footer PCK).
- **Extreme Performance & Multi-Threading**:
  - Powered by **OpenMP** parallel processing (scales automatically across all CPU cores).
  - Relaxed fast-path heuristic filtering for UTF-8 and dynamic paths.
  - Dynamic loading of OpenSSL `libcrypto` (`libcrypto-3-x64.dll`, `libcrypto.dll`, or `libcrypto-1_1-x64.dll`).

---

## 📋 Prerequisites

Before compiling or running, ensure you have:
1. **Windows 64-bit** (Windows 10, 11, or Windows Server).
2. **OpenSSL Runtime DLL**:
   - `libcrypto-3-x64.dll` or `libcrypto.dll` must be available in your system `PATH` or placed in the same folder as `godot_memd_key_finder.exe`.
   - If you have Git for Windows installed, `libcrypto-3-x64.dll` is already located in `C:\Program Files\Git\usr\bin\`.
3. **C Compiler** (for building from source):
   - [MinGW-w64 (GCC)](https://www.mingw-w64.org/) with OpenMP support.

---

## 🛠️ Compilation

Open a command prompt or terminal in the repository folder:

### Using MinGW-w64 (GCC) on Windows
```cmd
gcc -O3 -fopenmp godot_memd_key_finder.c -o godot_memd_key_finder.exe
```

### Cross-compiling from Linux targeting Windows x64
```bash
x86_64-w64-mingw32-gcc -O3 -fopenmp godot_memd_key_finder.c -o godot_memd_key_finder.exe
```

---

## 🚀 Usage & Examples

### 1. Live Breakpoint Hook Mode (Recommended)
Hooks the decryption routine directly in memory to intercept the key before zeroization:

```cmd
godot_memd_key_finder.exe --hook Game.exe
```

### 2. Extract All Resources to TAR Archive
Extracts all game resources, scripts, and scenes into a `.tar` package for translations and modding:

From an existing memory dump:
```cmd
godot_memd_key_finder.exe --dump-files memory.dmp game_resources.tar
```

Or launched live from the executable:
```cmd
godot_memd_key_finder.exe --dump-files Game.exe game_resources.tar
```

### 3. Automated Memory Dump Scanning
Automatically runs the game, captures its RAM state with a custom delay, extracts the key, and terminates the game process:

```cmd
godot_memd_key_finder.exe --auto Game.exe 6
```

### 4. Manual Memory Dump Scanning
If you already created a memory dump using **Task Manager** (`Right-click process -> Create dump file`):

```cmd
godot_memd_key_finder.exe Game.pck Game.dmp
```

### 5. Static Binary Scanning
Scans the game `.exe` directly in case the key is stored as static constant data in `.data` / `.rdata`:

```cmd
godot_memd_key_finder.exe Game.exe Game.exe
```

---

## 💡 Example Output

```text
=================================================================
 Godot Memory Dump & Extraction Key Finder v2.1 (Windows x64)
 Author: adisc (https://github.com/adisc99)
=================================================================

[*] Target PCK: Format v4, Type: PACK_DIR_ENCRYPTED, Expected MD5: 5f4572c0415e436beba90e72b65cd91c
[*] Detected open_and_parse() at RVA: 0x2B8CF30
[*] Debug session started (PID: 12488). Waiting for Godot decryption hook... hooked & verified!

=================================================================
 [+] AES-256 Key Intercepted via Live Hook!
     Hex: 25174114e542af3906b87ea59c031bb133f2c37d253705bff01892762bf9a437
=================================================================
```

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
