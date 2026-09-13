#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <initguid.h>
#include <virtdisk.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "../include/uf_boot_vhdx.h"
/* 이전 규약 헤더는 메모리 내 파서·ABI 회귀 시험에만 사용한다. 드라이버와 통신하지 않는다. */
#include "../../UF_BootProtectionFactory/include/uf_boot_protocol.h"

#define LAB_BYTES (256ull * 1024 * 1024)
#define LAB_SECTOR 512u
static HANDLE sLog = INVALID_HANDLE_VALUE;

C_ASSERT(sizeof(UF_BOOT_DEVICE_INFO) == 2000);
C_ASSERT(sizeof(UF_BOOT_DEVICE_LIST) == 64016);
C_ASSERT(sizeof(UF_BOOT_SET_REQUEST) == 32);

typedef struct _UF_LAB_PHASE {
    UF_BOOT_DEVICE_INFO BeforeState;
    UF_BOOT_DEVICE_INFO AfterState;
    DWORD WriteError[2];
    DWORD Written[2];
    BOOL WriteOk[2];
    ULONG Attempted;
    BOOL StateObserved;
    BOOL Passed;
    char BeforeHash[65];
    char AfterHash[65];
} UF_LAB_PHASE;

static void Log(const char* Stage, DWORD Error)
{
    char line[384];
    DWORD written;
    SYSTEMTIME now;
    GetSystemTime(&now);
    int n = sprintf_s(line, sizeof(line),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ stage=%s GetLastError=%lu\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
        now.wMilliseconds, Stage, Error);
    if (n > 0) {
        printf("%s", line);
        if (sLog != INVALID_HANDLE_VALUE &&
            (!WriteFile(sLog, line, (DWORD)n, &written, NULL) || written != (DWORD)n ||
             !FlushFileBuffers(sLog))) {
            printf("[ERROR] stage=write-log GetLastError=%lu\n", GetLastError());
        }
    }
}

static void Path(const wchar_t* Value)
{
    char utf8[2048];
    DWORD written;
    int n = WideCharToMultiByte(CP_UTF8, 0, Value, -1, utf8, sizeof(utf8), NULL, NULL);
    if (n > 0) {
        puts(utf8);
        if (sLog != INVALID_HANDLE_VALUE) {
            WriteFile(sLog, utf8, (DWORD)n - 1, &written, NULL);
            WriteFile(sLog, "\r\n", 2, &written, NULL);
        }
    }
}

static uint16_t U16(const BYTE* P) { return (uint16_t)(P[0] | ((uint16_t)P[1] << 8)); }
static uint32_t U32(const BYTE* P) { return (uint32_t)U16(P) | ((uint32_t)U16(P + 2) << 16); }
static uint64_t U64(const BYTE* P) { return U32(P) | ((uint64_t)U32(P + 4) << 32); }

/* 자체 포맷한 512바이트 섹터 볼륨만 지원한다. 범용 파일시스템 파서가 아니다. */
static int BackupOffset(const BYTE* Sector, int Fat32, uint64_t VolumeBytes, uint64_t* Offset)
{
    uint64_t sectors = VolumeBytes / LAB_SECTOR;
    if (VolumeBytes < 32ull * 1024 * 1024 || VolumeBytes >= LAB_BYTES ||
        VolumeBytes % LAB_SECTOR != 0 || U16(Sector + 11) != LAB_SECTOR ||
        Sector[510] != 0x55 || Sector[511] != 0xaa || Sector[13] == 0 ||
        (Sector[13] & (Sector[13] - 1)) != 0) return 0;
    if (Fat32) {
        uint16_t backup = U16(Sector + 50), reserved = U16(Sector + 14);
        if (memcmp(Sector + 82, "FAT32   ", 8) != 0 || U16(Sector + 17) != 0 ||
            U16(Sector + 19) != 0 || U16(Sector + 22) != 0 || U32(Sector + 36) == 0 ||
            U32(Sector + 32) != sectors || backup == 0 || backup >= reserved ||
            reserved >= sectors) return 0;
        *Offset = (uint64_t)backup * LAB_SECTOR;
    } else {
        uint64_t total = U64(Sector + 40);
        if (memcmp(Sector + 3, "NTFS    ", 8) != 0 || U16(Sector + 14) != 0 ||
            U16(Sector + 17) != 0 || U16(Sector + 19) != 0 || U16(Sector + 22) != 0 ||
            (total != sectors && total != sectors - 1)) return 0;
        *Offset = VolumeBytes - LAB_SECTOR;
    }
    return *Offset >= LAB_SECTOR && *Offset <= VolumeBytes - LAB_SECTOR;
}

static int GuestOnly(void)
{
    wchar_t product[128] = { 0 }, host[256] = { 0 };
    DWORD bytes = sizeof(product);
    LSTATUS r = RegGetValueW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
        L"SystemProductName", RRF_RT_REG_SZ, NULL, product, &bytes);
    if (r != ERROR_SUCCESS || wcscmp(product, L"Virtual Machine") != 0) {
        Log("refuse-not-hyperv-guest", ERROR_NOT_SUPPORTED); return 0;
    }
    bytes = sizeof(host);
    r = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"PhysicalHostName", RRF_RT_REG_SZ, NULL, host, &bytes);
    if (r != ERROR_SUCCESS || host[0] == 0) {
        Log("refuse-no-guest-integration-identity", ERROR_NOT_SUPPORTED); return 0;
    }
    {
        HANDLE token;
        TOKEN_ELEVATION elevation;
        DWORD returned;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            Log("query-elevation", GetLastError()); return 0;
        }
        BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
        CloseHandle(token);
        if (!ok || !elevation.TokenIsElevated) {
            Log("refuse-not-elevated", ERROR_ELEVATION_REQUIRED); return 0;
        }
    }
    return 1;
}

static HANDLE NewFile(const wchar_t* Directory, const wchar_t* Name)
{
    wchar_t path[MAX_PATH];
    if (swprintf_s(path, _countof(path), L"%ls\\%ls", Directory, Name) < 0) return INVALID_HANDLE_VALUE;
    return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}

static int Save(const wchar_t* Directory, const wchar_t* Name, const void* Bytes, DWORD Length)
{
    DWORD written = 0;
    HANDLE file = NewFile(Directory, Name);
    int ok;
    if (file == INVALID_HANDLE_VALUE) { Log("create-evidence-file", GetLastError()); return 0; }
    ok = WriteFile(file, Bytes, Length, &written, NULL) && written == Length && FlushFileBuffers(file);
    if (!ok) Log("write-evidence-file", GetLastError());
    CloseHandle(file);
    return ok;
}

static int ReadAt(HANDLE File, uint64_t Offset, void* Buffer, DWORD Length)
{
    LARGE_INTEGER position;
    DWORD read = 0;
    position.QuadPart = (LONGLONG)Offset;
    if (!SetFilePointerEx(File, position, NULL, FILE_BEGIN) ||
        !ReadFile(File, Buffer, Length, &read, NULL) || read != Length) {
        Log("read-sector", GetLastError()); return 0;
    }
    return 1;
}

static int Hash(const BYTE* Buffer, DWORD Length, char Text[65])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BYTE digest[32];
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    unsigned i;
    if (status >= 0) status = BCryptHash(alg, NULL, 0, (PUCHAR)Buffer, Length, digest, sizeof(digest));
    if (alg != NULL) BCryptCloseAlgorithmProvider(alg, 0);
    if (status < 0) { printf("stage=SHA256 NTSTATUS=0x%08lx\n", (ULONG)status); return 0; }
    for (i = 0; i < 32; ++i) sprintf_s(Text + i * 2, 65 - i * 2, "%02x", digest[i]);
    return 1;
}

static int SameDisk(HANDLE Disk, HANDLE Vhd, DWORD* Number)
{
    wchar_t path[MAX_PATH];
    ULONG pathBytes = sizeof(path);
    STORAGE_DEVICE_NUMBER number;
    GET_LENGTH_INFORMATION length;
    DISK_GEOMETRY geometry;
    STORAGE_PROPERTY_QUERY query = { StorageDeviceProperty, PropertyStandardQuery, {0} };
    BYTE descriptor[1024];
    DWORD returned;
    unsigned n;
    if (GetVirtualDiskPhysicalPath(Vhd, &pathBytes, path) != ERROR_SUCCESS ||
        swscanf_s(path, L"\\\\.\\PhysicalDrive%u", &n) != 1 ||
        !DeviceIoControl(Disk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &number, sizeof(number), &returned, NULL) ||
        !DeviceIoControl(Disk, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &length, sizeof(length), &returned, NULL) ||
        !DeviceIoControl(Disk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geometry, sizeof(geometry), &returned, NULL) ||
        !DeviceIoControl(Disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), descriptor, sizeof(descriptor), &returned, NULL) ||
        returned < sizeof(STORAGE_DEVICE_DESCRIPTOR) || number.DeviceType != FILE_DEVICE_DISK ||
        number.DeviceNumber != n || length.Length.QuadPart != LAB_BYTES ||
        geometry.BytesPerSector != LAB_SECTOR ||
        ((STORAGE_DEVICE_DESCRIPTOR*)descriptor)->BusType != BusTypeFileBackedVirtual) {
        Log("refuse-disk-identity-or-geometry", ERROR_INVALID_DATA); return 0;
    }
    *Number = number.DeviceNumber;
    return 1;
}

static int FormatNewDisk(DWORD Number, int Fat32, const wchar_t* Directory)
{
    wchar_t exe[MAX_PATH], system[MAX_PATH], command[2048];
    STARTUPINFOW startup = { sizeof(startup) };
    PROCESS_INFORMATION process = { 0 };
    HANDLE childLog;
    DWORD code = 1, wait;
    if (GetSystemDirectoryW(system, _countof(system)) == 0 ||
        swprintf_s(exe, _countof(exe), L"%ls\\WindowsPowerShell\\v1.0\\powershell.exe", system) < 0 ||
        swprintf_s(command, _countof(command),
        L"\"%ls\" -NoLogo -NoProfile -NonInteractive -Command \"& { [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; try { "
        L"$d=Get-Disk -Number %lu; if($d.IsBoot -or $d.IsSystem -or $d.IsOffline -or $d.IsReadOnly -or "
        L"$d.Size -ne 268435456 -or $d.LogicalSectorSize -ne 512 -or "
        L"$d.BusType -ne 'File Backed Virtual' -or $d.PartitionStyle -ne 'RAW') { throw 'target validation failed' }; "
        L"$d | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize | "
        L"Format-Volume -FileSystem %ls -NewFileSystemLabel UFBOOTLAB -Confirm:$false | Out-Null; exit 0 "
        L"} catch { Write-Error $_ -ErrorAction Continue; exit 1 } }\"", exe, Number, Fat32 ? L"FAT32" : L"NTFS") < 0) return 0;
    childLog = NewFile(Directory, L"format.log");
    if (childLog == INVALID_HANDLE_VALUE) { Log("create-format-log", GetLastError()); return 0; }
    if (!SetHandleInformation(childLog, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        Log("format-log-inheritance", GetLastError()); CloseHandle(childLog); return 0;
    }
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = startup.hStdError = startup.hStdInput = childLog;
    if (!CreateProcessW(exe, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        Log("start-format-owned-disk", GetLastError()); CloseHandle(childLog); return 0;
    }
    SetHandleInformation(childLog, HANDLE_FLAG_INHERIT, 0);
    CloseHandle(process.hThread);
    wait = WaitForSingleObject(process.hProcess, 120000);
    if (wait != WAIT_OBJECT_0) {
        /* 형식 작업 중 장치를 해제하지 않는다. 이 실행의 자식만 중단하고 종료를 확인한다. */
        TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(process.hProcess, INFINITE);
        Log("format-timeout", ERROR_TIMEOUT);
    } else if (!GetExitCodeProcess(process.hProcess, &code)) Log("format-exit-query", GetLastError());
    CloseHandle(process.hProcess);
    FlushFileBuffers(childLog);
    CloseHandle(childLog);
    if (code != 0) { Log("format-owned-disk-failed", ERROR_GEN_FAILURE); return 0; }
    return 1;
}

static HANDLE FindOwnedVolume(DWORD Number, int Fat32, uint64_t* Start, uint64_t* Length)
{
    wchar_t name[MAX_PATH], fs[32], label[64];
    HANDLE search = FindFirstVolumeW(name, _countof(name));
    HANDLE found = INVALID_HANDLE_VALUE;
    if (search == INVALID_HANDLE_VALUE) return found;
    do {
        VOLUME_DISK_EXTENTS extents;
        DWORD returned;
        HANDLE volume;
        size_t count = wcslen(name);
        if (count == 0 || name[count - 1] != L'\\') continue;
        name[count - 1] = 0;
        /* 다른 볼륨에는 조회 권한만 요청한다. 대상 확인 전 쓰기 핸들을 열지 않는다. */
        volume = CreateFileW(name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (volume == INVALID_HANDLE_VALUE) continue;
        if (DeviceIoControl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
            &extents, sizeof(extents), &returned, NULL) && returned >= sizeof(extents) &&
            extents.NumberOfDiskExtents == 1 && extents.Extents[0].DiskNumber == Number &&
            extents.Extents[0].StartingOffset.QuadPart >= 1024 * 1024 &&
            extents.Extents[0].ExtentLength.QuadPart > 0 &&
            (uint64_t)extents.Extents[0].ExtentLength.QuadPart < LAB_BYTES &&
            (uint64_t)extents.Extents[0].StartingOffset.QuadPart <=
                LAB_BYTES - (uint64_t)extents.Extents[0].ExtentLength.QuadPart) {
            CloseHandle(volume);
            volume = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
            if (volume != INVALID_HANDLE_VALUE &&
                GetVolumeInformationByHandleW(volume, label, _countof(label), NULL, NULL, NULL, fs, _countof(fs)) &&
                wcscmp(label, L"UFBOOTLAB") == 0 && wcscmp(fs, Fat32 ? L"FAT32" : L"NTFS") == 0) {
                *Start = (uint64_t)extents.Extents[0].StartingOffset.QuadPart;
                *Length = (uint64_t)extents.Extents[0].ExtentLength.QuadPart;
                found = volume;
                break;
            }
        }
        if (volume != INVALID_HANDLE_VALUE) CloseHandle(volume);
    } while (FindNextVolumeW(search, name, _countof(name)));
    FindVolumeClose(search);
    return found;
}

static int KernelInfoValid(const UF_BOOT_DEVICE_INFO* Info, DWORD Number, uint64_t ExpectedId)
{
    ULONG i;
    if (Info->Version != UF_BOOT_VERSION || Info->Size != sizeof(*Info) ||
        Info->DiskNumber != Number || Info->DeviceId == 0 ||
        (ExpectedId != 0 && Info->DeviceId != ExpectedId) ||
        Info->DiskBytes != LAB_BYTES || Info->SectorBytes != LAB_SECTOR ||
        (Info->Flags & (UF_BOOT_FLAG_LAB_DISK | UF_BOOT_FLAG_READY)) !=
            (UF_BOOT_FLAG_LAB_DISK | UF_BOOT_FLAG_READY) ||
        Info->RangeCount > UF_BOOT_MAX_RANGES ||
        (Info->State == UF_BOOT_ACTIVE && (Info->RangeCount == 0 || Info->PolicyGeneration == 0))) return 0;
    for (i = 0; i < Info->RangeCount; ++i) {
        const UF_BOOT_RANGE* range = &Info->Ranges[i];
        if (range->Reserved != 0 || range->Length == 0 || range->Offset >= LAB_BYTES ||
            range->Length > LAB_BYTES - range->Offset || range->Offset % LAB_SECTOR != 0 ||
            range->Length % LAB_SECTOR != 0) return 0;
    }
    return 1;
}

static int KernelCovers(const UF_BOOT_DEVICE_INFO* Info, uint64_t Offset, ULONG Kind)
{
    ULONG i;
    if (Offset > LAB_BYTES - LAB_SECTOR) return 0;
    for (i = 0; i < Info->RangeCount; ++i) {
        const UF_BOOT_RANGE* range = &Info->Ranges[i];
        if (range->Kind == Kind && range->Offset <= Offset && range->Length >= LAB_SECTOR &&
            Offset - range->Offset <= range->Length - LAB_SECTOR) return 1;
    }
    return 0;
}

static int PhasePassed(const UF_LAB_PHASE* Phase, int Active,
    const BYTE* Before, const BYTE* Damage, const BYTE* After)
{
    ULONG expected = Active ? UF_BOOT_ACTIVE : UF_BOOT_STOPPED;
    if (!Phase->StateObserved || Phase->Attempted != 2 ||
        Phase->BeforeState.State != expected || Phase->AfterState.State != expected ||
        Phase->BeforeState.DeviceId != Phase->AfterState.DeviceId ||
        Phase->BeforeState.PolicyGeneration != Phase->AfterState.PolicyGeneration) return 0;
    if (Active) return !Phase->WriteOk[0] && !Phase->WriteOk[1] &&
        Phase->WriteError[0] == ERROR_ACCESS_DENIED && Phase->WriteError[1] == ERROR_ACCESS_DENIED &&
        Phase->Written[0] == 0 && Phase->Written[1] == 0 && memcmp(After, Before, 2 * LAB_SECTOR) == 0 &&
        Phase->AfterState.BlockedWrites >= Phase->BeforeState.BlockedWrites &&
        Phase->AfterState.BlockedWrites - Phase->BeforeState.BlockedWrites >= 2;
    return Phase->WriteOk[0] && Phase->WriteOk[1] &&
        Phase->Written[0] == LAB_SECTOR && Phase->Written[1] == LAB_SECTOR &&
        memcmp(After, Damage, 2 * LAB_SECTOR) == 0 && memcmp(After, Before, 2 * LAB_SECTOR) != 0 &&
        Phase->AfterState.BlockedWrites == Phase->BeforeState.BlockedWrites;
}

static int RunVhdx(int Fat32)
{
    wchar_t temp[MAX_PATH], directory[MAX_PATH], vhdPath[MAX_PATH], physical[MAX_PATH], image[MAX_PATH];
    BYTE random[16];
    __declspec(align(4096)) BYTE before[1024], after[1024], damage[1024];
    char hex[33], json[1600], beforeHash[65], afterHash[65], message[160];
    HANDLE directoryHandle = INVALID_HANDLE_VALUE, vhd = INVALID_HANDLE_VALUE;
    HANDLE disk = INVALID_HANDLE_VALUE, volume = INVALID_HANDLE_VALUE;
    VIRTUAL_STORAGE_TYPE type = { VIRTUAL_STORAGE_TYPE_DEVICE_VHDX, VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT };
    CREATE_VIRTUAL_DISK_PARAMETERS create = { 0 };
    ATTACH_VIRTUAL_DISK_PARAMETERS attach = { 0 };
    BY_HANDLE_FILE_INFORMATION info;
    DWORD n, error, number = 0, returned, written[2] = {0}, writeError[2] = {0};
    BOOL writeOk[2] = {FALSE}, locked = FALSE, attached = FALSE;
    uint64_t start = 0, length = 0, backup = 0;
    unsigned i;
    int result = 1, verified = 0;
    ULONG physicalBytes = sizeof(physical);
    if (!GuestOnly()) return 1;
    puts("[실제 손상 시험] 새 폐기용 VHDX의 기본·백업 부트 섹터만 변경합니다.");
    n = GetTempPathW(_countof(temp), temp);
    if (n == 0 || n >= _countof(temp) || temp[1] != L':' || temp[2] != L'\\' ||
        GetDriveTypeW((wchar_t[4]){temp[0], L':', L'\\', 0}) != DRIVE_FIXED ||
        BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        Log("refuse-temp-or-random", ERROR_INVALID_DATA); return 1;
    }
    for (i = 0; i < sizeof(random); ++i) sprintf_s(hex + i * 2, sizeof(hex) - i * 2, "%02x", random[i]);
    if (swprintf_s(directory, _countof(directory), L"%lsUF_BootVhdx_%hs", temp, hex) < 0 ||
        !CreateDirectoryW(directory, NULL)) { Log("create-new-directory", GetLastError()); return 1; }
    directoryHandle = CreateFileW(directory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (directoryHandle == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(directoryHandle, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        Log("refuse-directory", ERROR_INVALID_DATA); goto Cleanup;
    }
    sLog = NewFile(directory, L"run.log");
    if (sLog == INVALID_HANDLE_VALUE) { Log("create-run-log", GetLastError()); goto Cleanup; }
    Path(directory);
    n = _countof(image);
    if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, image, &n)) Path(image);
    sprintf_s(message, sizeof(message), "begin-%s-pid-%lu", Fat32 ? "FAT32" : "NTFS", GetCurrentProcessId());
    Log(message, 0);
    if (swprintf_s(vhdPath, _countof(vhdPath), L"%ls\\disposable.vhdx", directory) < 0) goto Cleanup;
    create.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    create.Version2.MaximumSize = LAB_BYTES;
    create.Version2.SectorSizeInBytes = LAB_SECTOR;
    create.Version2.PhysicalSectorSizeInBytes = LAB_SECTOR;
    /* VERSION_2는 API 계약에 따라 ACCESS_NONE만 허용하며 핸들의 관리 권한은 API가 설정한다. */
    error = CreateVirtualDisk(&type, vhdPath, VIRTUAL_DISK_ACCESS_NONE, NULL,
        CREATE_VIRTUAL_DISK_FLAG_NONE, 0, &create, NULL, &vhd);
    if (error != ERROR_SUCCESS) { vhd = INVALID_HANDLE_VALUE; Log("create-new-vhdx", error); goto Cleanup; }
    attach.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
    error = AttachVirtualDisk(vhd, NULL, ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 0, &attach, NULL);
    if (error != ERROR_SUCCESS) { Log("attach-new-vhdx", error); goto Cleanup; }
    attached = TRUE;
    error = GetVirtualDiskPhysicalPath(vhd, &physicalBytes, physical);
    if (error != ERROR_SUCCESS) { Log("get-owned-physical-path", error); goto Cleanup; }
    disk = CreateFileW(physical, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    if (disk == INVALID_HANDLE_VALUE) { Log("open-owned-disk-readonly", GetLastError()); goto Cleanup; }
    if (!SameDisk(disk, vhd, &number) || !FormatNewDisk(number, Fat32, directory) || !SameDisk(disk, vhd, &number)) goto Cleanup;
    volume = FindOwnedVolume(number, Fat32, &start, &length);
    if (volume == INVALID_HANDLE_VALUE) { Log("find-owned-volume", ERROR_NOT_FOUND); goto Cleanup; }
    if (!DeviceIoControl(volume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &returned, NULL)) {
        Log("lock-owned-volume", GetLastError()); goto Cleanup;
    }
    locked = TRUE;
    if (!DeviceIoControl(volume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &returned, NULL)) {
        Log("dismount-owned-volume", GetLastError()); goto Cleanup;
    }
    if (!ReadAt(disk, start, before, LAB_SECTOR) || !BackupOffset(before, Fat32, length, &backup) ||
        !ReadAt(disk, start + backup, before + LAB_SECTOR, LAB_SECTOR) ||
        memcmp(before, before + LAB_SECTOR, LAB_SECTOR) != 0) {
        Log("refuse-unexpected-boot-layout", ERROR_INVALID_DATA); goto Cleanup;
    }
    if (!Save(directory, L"boot-before.bin", before, sizeof(before)) || !Hash(before, sizeof(before), beforeHash)) goto Cleanup;
    /* 검증한 파티션 마지막의 NTFS 백업 섹터까지 접근하되 자체 범위 검사는 유지한다. */
    if (!DeviceIoControl(volume, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &returned, NULL)) {
        Log("extended-io-owned-locked-volume", GetLastError()); goto Cleanup;
    }
    memcpy(damage, before, sizeof(damage));
    /* 부팅 코드와 서명만 무효화한다. 암호화·전파·OS 디스크 접근은 하지 않는다. */
    for (i = 0; i < 2; ++i) {
        BYTE* sector = damage + i * LAB_SECTOR;
        sector[0] = sector[1] = sector[2] = sector[510] = sector[511] = 0;
    }
    Log("baseline-saved-before-actual-writes", 0);
    for (i = 0; i < 2; ++i) {
        LARGE_INTEGER position;
        VOLUME_DISK_EXTENTS extents;
        /* 다시 연 핸들의 매핑도 잠금 상태에서 재검사한다. */
        if (!SameDisk(disk, vhd, &number) ||
            !DeviceIoControl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
                &extents, sizeof(extents), &returned, NULL) || returned < sizeof(extents) ||
            extents.NumberOfDiskExtents != 1 || extents.Extents[0].DiskNumber != number ||
            extents.Extents[0].StartingOffset.QuadPart != (LONGLONG)start ||
            extents.Extents[0].ExtentLength.QuadPart != (LONGLONG)length) {
            Log("refuse-revalidated-volume", ERROR_INVALID_DATA); goto Cleanup;
        }
        position.QuadPart = i == 0 ? 0 : (LONGLONG)backup;
        if (SetFilePointerEx(volume, position, NULL, FILE_BEGIN))
            writeOk[i] = WriteFile(volume, damage + i * LAB_SECTOR, LAB_SECTOR, &written[i], NULL);
        if (!writeOk[i]) writeError[i] = GetLastError();
        else if (written[i] != LAB_SECTOR) writeError[i] = ERROR_WRITE_FAULT;
        Log(i == 0 ? "actual-primary-write" : "actual-backup-write", writeError[i]);
    }
    if (!FlushFileBuffers(volume)) { Log("flush-volume", GetLastError()); goto Cleanup; }
    if (!ReadAt(disk, start, after, LAB_SECTOR) || !ReadAt(disk, start + backup, after + LAB_SECTOR, LAB_SECTOR) ||
        !Save(directory, L"boot-after.bin", after, sizeof(after)) || !Hash(after, sizeof(after), afterHash)) goto Cleanup;
    verified = writeOk[0] && writeOk[1] && written[0] == LAB_SECTOR && written[1] == LAB_SECTOR &&
        memcmp(after, damage, sizeof(after)) == 0 && memcmp(after, before, sizeof(after)) != 0;
    n = (DWORD)sprintf_s(json, sizeof(json),
        "{\"mode\":\"new-disposable-vhdx-actual-damage\",\"filesystem\":\"%s\","
        "\"kernelProtectionVerified\":false,\"osDiskTargeted\":false,\"diskNumber\":%lu,"
        "\"processId\":%lu,\"partitionOffset\":%llu,\"partitionBytes\":%llu,\"backupOffset\":%llu,"
        "\"primaryWriteError\":%lu,\"backupWriteError\":%lu,\"primaryWritten\":%lu,\"backupWritten\":%lu,"
        "\"beforeSha256\":\"%s\",\"afterSha256\":\"%s\",\"damageVerified\":%s}\r\n",
        Fat32 ? "FAT32" : "NTFS", number, GetCurrentProcessId(), start, length, backup,
        writeError[0], writeError[1], written[0], written[1], beforeHash, afterHash, verified ? "true" : "false");
    if (n >= sizeof(json) || !Save(directory, L"result.json", json, n)) goto Cleanup;
    Log(verified ? "damage-verified-not-a-protection-pass" : "damage-not-verified-not-a-protection-pass", 0);
    result = verified ? 0 : 1;
Cleanup:
    if (volume != INVALID_HANDLE_VALUE) {
        if (locked && !DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &returned, NULL))
            Log("unlock-volume", GetLastError());
        CloseHandle(volume);
    }
    if (disk != INVALID_HANDLE_VALUE) CloseHandle(disk);
    if (attached) {
        error = DetachVirtualDisk(vhd, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        Log("detach-owned-vhdx", error);
        if (error != ERROR_SUCCESS) result = 1;
    }
    if (vhd != INVALID_HANDLE_VALUE) CloseHandle(vhd);
    Log(result == 0 ? "completed-damaged-vhdx-retained" : "failed-see-stage-partial-damage-possible", 0);
    if (sLog != INVALID_HANDLE_VALUE) { CloseHandle(sLog); sLog = INVALID_HANDLE_VALUE; }
    if (directoryHandle != INVALID_HANDLE_VALUE) CloseHandle(directoryHandle);
    puts("시험 폴더는 삭제하지 않았습니다. 쓰기 거부만으로 보호 드라이버 성공이라고 판단하지 마세요.");
    return result;
}

int UfBootVhdxDamage(int Fat32) { return RunVhdx(Fat32); }

int UfBootVhdxSelfTest(void)
{
    BYTE sector[512] = {0};
    BYTE before[1024] = {0}, damage[1024] = {1};
    UF_BOOT_DEVICE_INFO state = {0};
    UF_LAB_PHASE phase = {0};
    uint64_t offset = 0, bytes = 64ull * 1024 * 1024;
    int failed = 0, count = 0;
#define VERIFY(X) do { ++count; if (!(X)) { ++failed; printf("[FAIL] line=%d\n", __LINE__); } } while (0)
    sector[11] = 0; sector[12] = 2; sector[13] = 1; sector[510] = 0x55; sector[511] = 0xaa;
    memcpy(sector + 3, "NTFS    ", 8); sector[42] = 2;
    VERIFY(BackupOffset(sector, 0, bytes, &offset) && offset == bytes - 512);
    sector[40] = 0xff; sector[41] = 0xff; sector[42] = 1;
    VERIFY(BackupOffset(sector, 0, bytes, &offset));
    sector[42] = 3; VERIFY(!BackupOffset(sector, 0, bytes, &offset));
    sector[42] = 1; sector[510] = 0; VERIFY(!BackupOffset(sector, 0, bytes, &offset));
    sector[510] = 0x55; sector[12] = 16; VERIFY(!BackupOffset(sector, 0, bytes, &offset));
    sector[12] = 2; VERIFY(!BackupOffset(sector, 0, LAB_BYTES, &offset));
    VERIFY(!BackupOffset(sector, 0, bytes - 1, &offset));
    VERIFY(!BackupOffset(sector, 0, UINT64_MAX, &offset));
    memcpy(sector + 82, "FAT32   ", 8); sector[14] = 32; sector[34] = 2; sector[36] = 1; sector[50] = 6;
    VERIFY(BackupOffset(sector, 1, bytes, &offset) && offset == 6 * 512);
    sector[50] = 0; VERIFY(!BackupOffset(sector, 1, bytes, &offset));
    sector[50] = 32; VERIFY(!BackupOffset(sector, 1, bytes, &offset));
    sector[50] = 6; sector[34] = 3; VERIFY(!BackupOffset(sector, 1, bytes, &offset));
    sector[34] = 2; sector[17] = 1; VERIFY(!BackupOffset(sector, 1, bytes, &offset));
    sector[17] = 0; sector[13] = 3; VERIFY(!BackupOffset(sector, 1, bytes, &offset));
    state.Version = UF_BOOT_VERSION; state.Size = sizeof(state);
    state.DeviceId = 42; state.PolicyGeneration = 1; state.DiskNumber = 7;
    state.DiskBytes = LAB_BYTES; state.SectorBytes = LAB_SECTOR;
    state.Flags = UF_BOOT_FLAG_LAB_DISK | UF_BOOT_FLAG_READY; state.State = UF_BOOT_STOPPED;
    VERIFY(KernelInfoValid(&state, 7, 42));
    VERIFY(!KernelInfoValid(&state, 8, 42));
    VERIFY(!KernelInfoValid(&state, 7, 43));
    state.State = UF_BOOT_ACTIVE; VERIFY(!KernelInfoValid(&state, 7, 42));
    state.RangeCount = 1; state.Ranges[0].Offset = 1024 * 1024;
    state.Ranges[0].Length = 3 * LAB_SECTOR; state.Ranges[0].Kind = UF_BOOT_KIND_FAT32;
    VERIFY(KernelInfoValid(&state, 7, 42));
    VERIFY(KernelCovers(&state, 1024 * 1024, UF_BOOT_KIND_FAT32));
    VERIFY(KernelCovers(&state, 1024 * 1024 + 2 * LAB_SECTOR, UF_BOOT_KIND_FAT32));
    VERIFY(!KernelCovers(&state, 1024 * 1024 + 3 * LAB_SECTOR, UF_BOOT_KIND_FAT32));
    VERIFY(!KernelCovers(&state, 1024 * 1024 - 1, UF_BOOT_KIND_FAT32));
    VERIFY(!KernelCovers(&state, 1024 * 1024, UF_BOOT_KIND_NTFS));
    VERIFY(!KernelCovers(&state, UINT64_MAX, UF_BOOT_KIND_FAT32));
    state.Ranges[0].Length = UINT64_MAX; VERIFY(!KernelInfoValid(&state, 7, 42));
    state.Ranges[0].Length = LAB_SECTOR; state.Flags = UF_BOOT_FLAG_READY;
    VERIFY(!KernelInfoValid(&state, 7, 42));
    state.Flags |= UF_BOOT_FLAG_LAB_DISK; state.Version++;
    VERIFY(!KernelInfoValid(&state, 7, 42));
    state.Version = UF_BOOT_VERSION; state.RangeCount = UF_BOOT_MAX_RANGES + 1;
    VERIFY(!KernelInfoValid(&state, 7, 42));
    phase.StateObserved = TRUE; phase.Attempted = 2;
    phase.BeforeState.State = phase.AfterState.State = UF_BOOT_ACTIVE;
    phase.BeforeState.DeviceId = phase.AfterState.DeviceId = 42;
    phase.BeforeState.PolicyGeneration = phase.AfterState.PolicyGeneration = 1;
    phase.AfterState.BlockedWrites = 2;
    phase.WriteError[0] = phase.WriteError[1] = ERROR_ACCESS_DENIED;
    VERIFY(PhasePassed(&phase, 1, before, damage, before));
    phase.AfterState.BlockedWrites = 0; VERIFY(!PhasePassed(&phase, 1, before, damage, before));
    phase.AfterState.BlockedWrites = 2; phase.WriteError[0] = ERROR_WRITE_PROTECT;
    VERIFY(!PhasePassed(&phase, 1, before, damage, before));
    phase.WriteError[0] = ERROR_ACCESS_DENIED;
    VERIFY(!PhasePassed(&phase, 1, before, damage, damage));
    phase.AfterState.DeviceId++; VERIFY(!PhasePassed(&phase, 1, before, damage, before));
    phase.AfterState.DeviceId--; phase.AfterState.PolicyGeneration++;
    VERIFY(!PhasePassed(&phase, 1, before, damage, before));
    phase.AfterState.PolicyGeneration--; phase.AfterState.State = UF_BOOT_STOPPED;
    VERIFY(!PhasePassed(&phase, 1, before, damage, before));
    phase.BeforeState.State = UF_BOOT_STOPPED; phase.BeforeState.BlockedWrites = 2;
    phase.WriteOk[0] = phase.WriteOk[1] = TRUE; phase.Written[0] = phase.Written[1] = LAB_SECTOR;
    phase.WriteError[0] = phase.WriteError[1] = 0;
    VERIFY(PhasePassed(&phase, 0, before, damage, damage));
    VERIFY(!PhasePassed(&phase, 0, before, damage, before));
    phase.Written[1]--; VERIFY(!PhasePassed(&phase, 0, before, damage, damage));
    phase.Written[1]++; phase.Attempted = 1;
    VERIFY(!PhasePassed(&phase, 0, before, damage, damage));
    printf("VHDX layout/archived-ABI checks=%d failed=%d (no device I/O; not a minifilter protection test)\n", count, failed);
    return failed ? 1 : 0;
#undef VERIFY
}
