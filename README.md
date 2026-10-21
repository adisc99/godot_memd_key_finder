# Godot Memory Dump AES-256 Key Finder (`godot_memd_key_finder`)

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)](https://github.com/adisc99/godot_memd_key_finder)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)](godot_memd_key_finder.c)

A high-performance, multi-threaded C tool designed to recover **AES-256 encryption keys** from **Godot Engine** games using runtime memory dumps (RAM) or static binary analysis.

Developed by [adisc](https://github.com/adisc99).

---

> [!IMPORTANT]
> **Windows-Only Tool**: This program relies on native Windows APIs (`CreateProcessA`, `MiniDumpWriteDump`, `dbghelp.dll`) to launch processes and capture memory dumps on the fly. It is designed and compiled specifically for **Windows x64**.

---

## 🎯 Features

- **Automated Memory Dumping (`--auto`)**:
  - Automatically launches the target Godot game in hidden mode.
  - Waits for Godot's engine initialization (PCK loading & key decryption).
  - Captures a complete process memory dump (`MiniDumpWithFullMemory` via `dbghelp.dll`).
  - Scans RAM for the 256-bit AES key and safely cleans up temporary dump files.
- **Support for All Godot PCK Versions**:
  - Godot 3.x and 4.x PCK archives (Format v1, v2, and v3).
  - Encrypted Pack Directories (`PACK_DIR_ENCRYPTED`).
  - Individually encrypted internal resources (scripts, scenes, images).
  - Standalone `.pck` files and embedded executables (PE sections or footer PCK).
- **Extreme Performance & Multi-Threading**:
  - Powered by **OpenMP** parallel processing (scales automatically across all CPU cores).
  - Fast-path 16-byte heuristic filtering: rejects non-matching candidates before running costly full-block MD5 checksums.
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
If you have `mingw-w64` installed on Linux:
```bash
x86_64-w64-mingw32-gcc -O3 -fopenmp godot_memd_key_finder.c -o godot_memd_key_finder.exe
```

---

## 🚀 Usage & Examples

### 1. Fully Automated Mode (Recommended)
Automatically runs the game, captures its RAM state, extracts the key, and terminates the game process:

```cmd
godot_memd_key_finder.exe --auto Game.exe
```

*(You can also use `-a` or simply provide the executable if it ends in `.exe`)*:
```cmd
godot_memd_key_finder.exe Game.exe
```

### 2. Manual Memory Dump Scanning
If you already created a memory dump using **Task Manager** (`Right-click process -> Create dump file`) or **Process Hacker**:

```cmd
godot_memd_key_finder.exe Game.pck Game.dmp
```
or with embedded executables:
```cmd
godot_memd_key_finder.exe Game.exe Game.dmp
```

### 3. Static Binary Scanning
You can scan the game `.exe` directly without launching it (in case the key is stored as static constant data in `.data` / `.rdata`):

```cmd
godot_memd_key_finder.exe Game.exe Game.exe
```

---

## 💡 Example Output

```text
=================================================================
 Godot Memory Dump AES-256 Key Finder v1.4 (Windows x64)
 Author: adisc (https://github.com/adisc99)
=================================================================

[*] Process started (PID: 12488). Waiting for Godot initialization... done.
[*] Scanning 184 MB for 256-bit AES key...
[*] Scan completed in 0.85 seconds using 16 threads.

=================================================================
 [+] AES-256 Key Found!
     Hex: 25174114e542af3906b87ea59c031bb133f2c37d253705bff01892762bf9a437
=================================================================
```

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
