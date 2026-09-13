#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../include/uf_boot_range.h"
#include "../include/uf_boot_vhdx.h"

#define SCENARIO_COUNT 30u
#define FIXTURE_SECTORS 2048u
#define TEST_NOW 500u
static unsigned gChecks;
static unsigned gFailed;
static unsigned gRecords;
static HANDLE gReport = INVALID_HANDLE_VALUE;

typedef struct SCENARIO {
    const char* Name;
    UF_BOOT_WRITE_REQUEST Request;
    UF_BOOT_MAINTENANCE_PERMIT Permit;
    int HasPermit;
    UF_BOOT_VERDICT Expected;
} SCENARIO;

static void Check(int Passed, const char* Name)
{
    ++gChecks;
    if (!Passed) ++gFailed;
    printf("[%s] %s\n", Passed ? "PASS" : "FAIL", Name);
}

static int ErrorWin32(const char* Stage, DWORD Error)
{
    printf("[ERROR] stage=%s GetLastError=%lu\n", Stage, Error);
    return 0;
}

static int ErrorCng(const char* Stage, NTSTATUS Status)
{
    printf("[ERROR] stage=%s NTSTATUS=0x%08lX\n", Stage, (ULONG)Status);
    return 0;
}

static void PrintPath(const wchar_t* Path)
{
    char utf8[4096];
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, Path, -1,
            utf8, sizeof(utf8), NULL, NULL) != 0) {
        printf("%s\n", utf8);
    }
}

static UF_BOOT_RANGE_POLICY FixturePolicy(uint32_t Sector)
{
    /* 실파일시스템 배치가 아닌 고정 합성 영역이다. BPB나 GPT를 파싱하지 않는다. */
    UF_BOOT_RANGE_POLICY p = { 0 };
    const uint32_t starts[] = { 0, 1, 64, 70, 128, 511, 2015 };
    const uint32_t lengths[] = { 1, 32, 3, 3, 16, 1, 33 };
    unsigned i;
    p.DeviceToken = 7;
    p.Generation = 3;
    p.DiskBytes = (uint64_t)FIXTURE_SECTORS * Sector;
    p.SectorBytes = Sector;
    p.RangeCount = (uint32_t)_countof(starts);
    for (i = 0; i < p.RangeCount; ++i) {
        p.Ranges[i].Id = i + 1;
        p.Ranges[i].Offset = (uint64_t)starts[i] * Sector;
        p.Ranges[i].Length = (uint64_t)lengths[i] * Sector;
    }
    return p;
}

static SCENARIO MakeScenario(unsigned Index, uint32_t Sector)
{
    SCENARIO s = { 0 };
    uint64_t unit = Sector;
    s.Request.DeviceToken = 7;
    s.Request.Generation = 3;
    s.Request.Offset = 64 * unit;
    s.Request.Length = unit;
    s.Request.ProcessId = 100;
    s.Request.ProcessCreated = 200;
    s.Request.RequestorKnown = 1;
    s.Permit.DeviceToken = 7;
    s.Permit.Generation = 3;
    s.Permit.ProcessId = 100;
    s.Permit.ProcessCreated = 200;
    s.Permit.Offset = 64 * unit;
    s.Permit.Length = 3 * unit;
    s.Permit.ExpiresAt = TEST_NOW + 1;
    s.Permit.RangeId = 3;
    s.Expected = UfBootBlock;
    switch (Index) {
    case 0: s.Name = "mbr-fixture"; s.Request.Offset = 0; break;
    case 1: s.Name = "gpt-primary-fixture"; s.Request.Offset = unit; break;
    case 2: s.Name = "fat32-primary-fixture"; break;
    case 3: s.Name = "fat32-backup-fixture"; s.Request.Offset = 70 * unit; break;
    case 4: s.Name = "ntfs-primary-fixture"; s.Request.Offset = 128 * unit; break;
    case 5: s.Name = "ntfs-backup-fixture"; s.Request.Offset = 511 * unit; break;
    case 6: s.Name = "gpt-backup-fixture"; s.Request.Offset = 2015 * unit; break;
    case 7: s.Name = "outside-range"; s.Request.Offset = 256 * unit; s.Expected = UfBootAllow; break;
    case 8: s.Name = "ends-at-protected-start"; s.Request.Offset = 63 * unit; s.Expected = UfBootAllow; break;
    case 9: s.Name = "crosses-protected-start"; s.Request.Offset -= 1; s.Request.Length = 2; break;
    case 10: s.Name = "starts-at-protected-end"; s.Request.Offset = 67 * unit; s.Expected = UfBootAllow; break;
    case 11: s.Name = "crosses-protected-end"; s.Request.Offset = 67 * unit - 1; s.Request.Length = 2; break;
    case 12: s.Name = "last-disk-byte"; s.Request.Offset = FIXTURE_SECTORS * unit - 1; s.Request.Length = 1; break;
    case 13: s.Name = "beyond-disk"; s.Request.Offset = FIXTURE_SECTORS * unit; s.Expected = UfBootInvalid; break;
    case 14: s.Name = "zero-length"; s.Request.Length = 0; s.Expected = UfBootInvalid; break;
    case 15: s.Name = "offset-overflow"; s.Request.Offset = UINT64_MAX - 1; s.Request.Length = 4; s.Expected = UfBootInvalid; break;
    case 16: s.Name = "unknown-requestor"; s.Request.RequestorKnown = 0; break;
    case 17: s.Name = "maintenance-valid"; s.HasPermit = 1; s.Expected = UfBootAllow; break;
    case 18: s.Name = "maintenance-expired"; s.HasPermit = 1; s.Permit.ExpiresAt = TEST_NOW; break;
    case 19: s.Name = "maintenance-other-pid"; s.HasPermit = 1; s.Permit.ProcessId++; break;
    case 20: s.Name = "maintenance-pid-reused"; s.HasPermit = 1; s.Permit.ProcessCreated++; break;
    case 21: s.Name = "maintenance-stale-policy"; s.HasPermit = 1; s.Permit.Generation++; break;
    case 22: s.Name = "maintenance-other-device"; s.HasPermit = 1; s.Permit.DeviceToken++; break;
    case 23: s.Name = "maintenance-unknown-requestor"; s.HasPermit = 1; s.Request.RequestorKnown = 0; break;
    case 24: s.Name = "request-other-device"; s.Request.DeviceToken++; s.Expected = UfBootNotCovered; break;
    case 25: s.Name = "request-stale-generation"; s.Request.Generation++; s.Expected = UfBootInvalid; break;
    case 26: s.Name = "maintenance-wrong-range"; s.HasPermit = 1; s.Permit.RangeId++; break;
    case 27: s.Name = "maintenance-overflow"; s.HasPermit = 1; s.Permit.Length = UINT64_MAX; break;
    case 28: s.Name = "contains-all-ranges"; s.HasPermit = 1; s.Request.Offset = 0; s.Request.Length = FIXTURE_SECTORS * unit; break;
    default: s.Name = "maintenance-exceeds-grant"; s.HasPermit = 1; s.Permit.Length = unit / 2; break;
    }
    return s;
}

static uint64_t NextRandom(uint64_t* State)
{
    *State ^= *State << 13;
    *State ^= *State >> 7;
    *State ^= *State << 17;
    return *State;
}

static void SelfTest(void)
{
    const uint32_t sectors[] = { 512, 4096 };
    unsigned k, i;
    for (k = 0; k < _countof(sectors); ++k) {
        UF_BOOT_RANGE_POLICY p = FixturePolicy(sectors[k]);
        UF_BOOT_WRITE_REQUEST request = MakeScenario(2, sectors[k]).Request;
        unsigned char* oracle;
        uint64_t random = 0x36597A51u;
        int matches = 1;
        printf("\n[단위 시험] sectorBytes=%u\n", sectors[k]);
        Check(UfBootValidateRangePolicy(&p), "valid-policy");
        for (i = 0; i < SCENARIO_COUNT; ++i) {
            SCENARIO s = MakeScenario(i, sectors[k]);
            UF_BOOT_DECISION d = UfBootEvaluateWrite(&p, &s.Request,
                s.HasPermit ? &s.Permit : NULL, TEST_NOW);
            Check(d.Verdict == s.Expected, s.Name);
            if (i == 17) Check(d.Reason == UfBootMaintenanceAllowed && d.RangeId == 3, "maintenance-reason-and-range");
        }
        /* 독립 기준은 바이트별 보호 비트맵이다. 구간 교차식을 재사용하지 않는다. */
        oracle = calloc((size_t)p.DiskBytes, 1);
        if (oracle == NULL) { Check(0, "oracle-allocation"); continue; }
        for (i = 0; i < p.RangeCount; ++i) {
            memset(oracle + (size_t)p.Ranges[i].Offset, 1, (size_t)p.Ranges[i].Length);
        }
        for (i = 0; i < 10000; ++i) {
            uint64_t j;
            UF_BOOT_VERDICT expected = UfBootAllow;
            request.Offset = NextRandom(&random) % p.DiskBytes;
            request.Length = 1 + NextRandom(&random) % 2048;
            if (request.Length > p.DiskBytes - request.Offset) {
                expected = UfBootInvalid;
            } else {
                for (j = request.Offset; j < request.Offset + request.Length; ++j) {
                    if (oracle[(size_t)j]) { expected = UfBootBlock; break; }
                }
            }
            if (UfBootEvaluateWrite(&p, &request, NULL, TEST_NOW).Verdict != expected) {
                printf("oracle mismatch index=%u offset=%llu length=%llu\n", i, request.Offset, request.Length);
                matches = 0; break;
            }
        }
        Check(matches, "independent-byte-oracle-10000");
        free(oracle);
    }
    for (i = 0; i < 14; ++i) {
        UF_BOOT_RANGE_POLICY p = FixturePolicy(512);
        const char* name;
        switch (i) {
        case 0: name = "policy-zero-device"; p.DeviceToken = 0; break;
        case 1: name = "policy-zero-generation"; p.Generation = 0; break;
        case 2: name = "policy-sector-unsupported"; p.SectorBytes = 1000; break;
        case 3: name = "policy-empty-disk"; p.DiskBytes = 0; break;
        case 4: name = "policy-unaligned-disk"; p.DiskBytes--; break;
        case 5: name = "policy-empty-ranges"; p.RangeCount = 0; break;
        case 6: name = "policy-too-many-ranges"; p.RangeCount = UF_BOOT_RANGE_LIMIT + 1; break;
        case 7: name = "policy-zero-range-id"; p.Ranges[0].Id = 0; break;
        case 8: name = "policy-duplicate-id"; p.Ranges[1].Id = p.Ranges[0].Id; break;
        case 9: name = "policy-overlap"; p.Ranges[1].Offset = 0; break;
        case 10: name = "policy-empty-range"; p.Ranges[0].Length = 0; break;
        case 11: name = "policy-overflow-range"; p.Ranges[0].Length = UINT64_MAX; break;
        case 12: name = "policy-unaligned-offset"; p.Ranges[1].Offset++; break;
        default: name = "policy-unaligned-length"; p.Ranges[1].Length++; break;
        }
        Check(!UfBootValidateRangePolicy(&p), name);
    }
    {
        UF_BOOT_RANGE_POLICY p = FixturePolicy(512);
        SCENARIO s = MakeScenario(17, 512);
        Check(UfBootEvaluateWrite(NULL, &s.Request, NULL, TEST_NOW).Verdict == UfBootInvalid, "null-policy");
        Check(UfBootEvaluateWrite(&p, NULL, NULL, TEST_NOW).Verdict == UfBootInvalid, "null-request");
        s.Request.RequestorKnown = 2;
        Check(UfBootEvaluateWrite(&p, &s.Request, NULL, TEST_NOW).Verdict == UfBootInvalid, "invalid-known-flag");
        s.Request.RequestorKnown = 1; s.Request.ProcessId = 0; s.Permit.ProcessId = 0;
        Check(UfBootEvaluateWrite(&p, &s.Request, &s.Permit, TEST_NOW).Verdict == UfBootBlock, "zero-pid-not-authorized");
        s.Request.ProcessId = 100; s.Permit.ProcessId = 100;
        s.Request.ProcessCreated = 0; s.Permit.ProcessCreated = 0;
        Check(UfBootEvaluateWrite(&p, &s.Request, &s.Permit, TEST_NOW).Verdict == UfBootBlock, "zero-created-not-authorized");
    }
}

static int WriteExact(HANDLE File, const void* Buffer, DWORD Length)
{
    DWORD done = 0;
    if (!WriteFile(File, Buffer, Length, &done, NULL)) return ErrorWin32("WriteFile", GetLastError());
    return done == Length ? 1 : ErrorWin32("short-write", ERROR_WRITE_FAULT);
}

static int Seek(HANDLE File, uint64_t Position)
{
    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)Position;
    if (!SetFilePointerEx(File, offset, NULL, FILE_BEGIN)) return ErrorWin32("SetFilePointerEx", GetLastError());
    return 1;
}

static HANDLE CreateOwnedFile(const wchar_t* Path)
{
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE file = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) { ErrorWin32("CreateFile(CREATE_NEW)", GetLastError()); return file; }
    if (!GetFileInformationByHandle(file, &info)) {
        DWORD error = GetLastError(); CloseHandle(file); ErrorWin32("GetFileInformationByHandle", error); return INVALID_HANDLE_VALUE;
    }
    if (GetFileType(file) != FILE_TYPE_DISK || info.nNumberOfLinks != 1 ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        info.nFileSizeHigh != 0 || info.nFileSizeLow != 0) {
        CloseHandle(file); ErrorWin32("new-regular-file-check", ERROR_INVALID_DATA); return INVALID_HANDLE_VALUE;
    }
    return file;
}

static int ReadImage(HANDLE File, unsigned char* Bytes, DWORD Size)
{
    DWORD done;
    LARGE_INTEGER length;
    if (!GetFileSizeEx(File, &length)) return ErrorWin32("GetFileSizeEx", GetLastError());
    if (length.QuadPart != Size) return ErrorWin32("fixture-size", ERROR_INVALID_DATA);
    if (!Seek(File, 0)) return 0;
    if (!ReadFile(File, Bytes, Size, &done, NULL)) return ErrorWin32("ReadFile", GetLastError());
    return done == Size ? 1 : ErrorWin32("short-read", ERROR_READ_FAULT);
}

static int Hash(BCRYPT_ALG_HANDLE Alg, unsigned char* Bytes, DWORD Size, char Hex[65])
{
    unsigned char digest[32];
    unsigned i;
    static const char digits[] = "0123456789abcdef";
    NTSTATUS status = BCryptHash(Alg, NULL, 0, Bytes, Size, digest, sizeof(digest));
    if (status < 0) return ErrorCng("BCryptHash", status);
    for (i = 0; i < sizeof(digest); ++i) {
        Hex[i * 2] = digits[digest[i] >> 4];
        Hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    Hex[64] = 0;
    return 1;
}

static const char* VerdictName(UF_BOOT_VERDICT Verdict)
{
    switch (Verdict) {
    case UfBootAllow: return "ALLOW";
    case UfBootBlock: return "BLOCK";
    case UfBootNotCovered: return "NOT_COVERED";
    default: return "INVALID";
    }
}

static int ImageFixture(const wchar_t* Directory, uint32_t Sector, BCRYPT_ALG_HANDLE Alg)
{
    wchar_t path[MAX_PATH];
    UF_BOOT_RANGE_POLICY p = FixturePolicy(Sector);
    DWORD size = (DWORD)p.DiskBytes;
    unsigned char* before = NULL;
    unsigned char* after = NULL;
    unsigned char* expected = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    unsigned i;
    int success = 0;
    if (swprintf_s(path, _countof(path), L"%ls\\synthetic-%u.fixture.bin", Directory, Sector) < 0) return 0;
    before = malloc(size); after = malloc(size); expected = malloc(size);
    if (before == NULL || after == NULL || expected == NULL) { ErrorWin32("malloc", ERROR_NOT_ENOUGH_MEMORY); goto Cleanup; }
    for (i = 0; i < size; ++i) before[i] = (unsigned char)(i % 251);
    file = CreateOwnedFile(path);
    if (file == INVALID_HANDLE_VALUE || !WriteExact(file, before, size)) goto Cleanup;
    printf("\n[파일 모의 시험] sectorBytes=%u; 실제 FAT32/NTFS/VHDX가 아닙니다.\n", Sector);
    PrintPath(path);
    for (i = 0; i < SCENARIO_COUNT; ++i) {
        SCENARIO s = MakeScenario(i, Sector);
        UF_BOOT_DECISION d = UfBootEvaluateWrite(&p, &s.Request, s.HasPermit ? &s.Permit : NULL, TEST_NOW);
        char beforeHash[65], afterHash[65], record[1024];
        uint64_t j;
        int contentOk, passed;
        int writeCalled = 0;
        if (!ReadImage(file, before, size) || !Hash(Alg, before, size, beforeHash)) goto Cleanup;
        memcpy(expected, before, size);
        if (s.Expected == UfBootAllow) {
            for (j = s.Request.Offset; j < s.Request.Offset + s.Request.Length; ++j) expected[(size_t)j] ^= 0x5a;
        }
        if (d.Verdict == UfBootAllow) {
            /* 판정 모듈에 오류가 있어도 이 핸들의 시험 파일 경계는 별도로 제한한다. */
            if (s.Request.Length == 0 || s.Request.Offset >= size || s.Request.Length > size - s.Request.Offset) {
                ErrorWin32("fixture-write-boundary", ERROR_INVALID_DATA); goto Cleanup;
            }
            memcpy(after, before, size);
            for (j = s.Request.Offset; j < s.Request.Offset + s.Request.Length; ++j) after[(size_t)j] ^= 0x5a;
            if (!Seek(file, s.Request.Offset) ||
                !WriteExact(file, after + (size_t)s.Request.Offset, (DWORD)s.Request.Length)) goto Cleanup;
            writeCalled = 1;
        }
        if (!FlushFileBuffers(file)) { ErrorWin32("FlushFileBuffers", GetLastError()); goto Cleanup; }
        if (!ReadImage(file, after, size) || !Hash(Alg, after, size, afterHash)) goto Cleanup;
        contentOk = memcmp(expected, after, size) == 0;
        passed = d.Verdict == s.Expected && contentOk &&
            ((strcmp(beforeHash, afterHash) != 0) == (s.Expected == UfBootAllow));
        Check(passed, s.Name);
        printf("  model=%s reason=%u range=%u offset=%llu length=%llu\n  before=%s\n  after =%s\n",
            VerdictName(d.Verdict), (unsigned)d.Reason, d.RangeId, s.Request.Offset, s.Request.Length, beforeHash, afterHash);
        if (sprintf_s(record, sizeof(record),
            "%s{\"case\":\"%s\",\"sectorBytes\":%u,\"offset\":%llu,\"length\":%llu,"
            "\"expected\":\"%s\",\"actual\":\"%s\",\"reason\":%u,\"rangeId\":%u,"
            "\"writeCalled\":%s,\"beforeSha256\":\"%s\",\"afterSha256\":\"%s\",\"passed\":%s}",
            gRecords ? ",\r\n" : "", s.Name, Sector, s.Request.Offset, s.Request.Length,
            VerdictName(s.Expected), VerdictName(d.Verdict), (unsigned)d.Reason, d.RangeId,
            writeCalled ? "true" : "false", beforeHash, afterHash, passed ? "true" : "false") < 0) goto Cleanup;
        if (!WriteExact(gReport, record, (DWORD)strlen(record))) goto Cleanup;
        ++gRecords;
    }
    success = 1;
Cleanup:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(before); free(after); free(expected);
    return success;
}

static void ImageTest(void)
{
    wchar_t temp[MAX_PATH], directory[MAX_PATH], reportPath[MAX_PATH];
    wchar_t root[4];
    uint64_t random[2];
    BCRYPT_ALG_HANDLE alg = NULL;
    HANDLE directoryHandle = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    NTSTATUS status;
    DWORD tempLength;
    int success = 0;
    char summary[256];
    const char begin[] = "{\"mode\":\"regular-file-simulation\",\"kernelDriverTested\":false,\"realDiskWritten\":false,\"cases\":[\r\n";
    tempLength = GetTempPathW(_countof(temp), temp);
    if (tempLength == 0 || tempLength >= _countof(temp)) { ErrorWin32("GetTempPathW", tempLength ? ERROR_INSUFFICIENT_BUFFER : GetLastError()); goto Cleanup; }
    /* UNC·장치 경로 입력은 받지 않으며 로컬 고정 드라이브의 임시 위치만 사용한다. */
    if (tempLength < 3 || !((temp[0] >= L'A' && temp[0] <= L'Z') || (temp[0] >= L'a' && temp[0] <= L'z')) ||
        temp[1] != L':' || temp[2] != L'\\' || wcschr(temp + 2, L':') != NULL) {
        ErrorWin32("local-temp-path-required", ERROR_BAD_PATHNAME); goto Cleanup;
    }
    root[0] = temp[0]; root[1] = L':'; root[2] = L'\\'; root[3] = 0;
    if (GetDriveTypeW(root) != DRIVE_FIXED) { ErrorWin32("fixed-temp-drive-required", ERROR_NOT_SUPPORTED); goto Cleanup; }
    status = BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) { ErrorCng("BCryptGenRandom", status); goto Cleanup; }
    if (swprintf_s(directory, _countof(directory), L"%lsUF_BootProtectionTest_%016llx%016llx", temp, random[0], random[1]) < 0) goto Cleanup;
    if (!CreateDirectoryW(directory, NULL)) { ErrorWin32("CreateDirectory", GetLastError()); goto Cleanup; }
    printf("\n시험 자료를 보관할 새 폴더:\n"); PrintPath(directory);
    directoryHandle = CreateFileW(directory, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (directoryHandle == INVALID_HANDLE_VALUE) { ErrorWin32("open-created-directory", GetLastError()); goto Cleanup; }
    if (!GetFileInformationByHandle(directoryHandle, &info)) { ErrorWin32("query-created-directory", GetLastError()); goto Cleanup; }
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        ErrorWin32("created-directory-reparse-check", ERROR_INVALID_DATA); goto Cleanup;
    }
    if (swprintf_s(reportPath, _countof(reportPath), L"%ls\\result.json", directory) < 0) goto Cleanup;
    gReport = CreateOwnedFile(reportPath);
    if (gReport == INVALID_HANDLE_VALUE || !WriteExact(gReport, begin, sizeof(begin) - 1)) goto Cleanup;
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) { ErrorCng("BCryptOpenAlgorithmProvider", status); goto FinishReport; }
    success = ImageFixture(directory, 512, alg) && ImageFixture(directory, 4096, alg);
FinishReport:
    if (sprintf_s(summary, sizeof(summary), "\r\n],\"completed\":%s,\"caseCount\":%u,\"checks\":%u,\"failedChecks\":%u}\r\n",
        success ? "true" : "false", gRecords, gChecks, gFailed) < 0 ||
        !WriteExact(gReport, summary, (DWORD)strlen(summary))) success = 0;
    if (!FlushFileBuffers(gReport)) { ErrorWin32("flush-report", GetLastError()); success = 0; }
    printf("\nJSON 보고서:\n"); PrintPath(reportPath);
Cleanup:
    if (gReport != INVALID_HANDLE_VALUE) { CloseHandle(gReport); gReport = INVALID_HANDLE_VALUE; }
    if (alg != NULL) BCryptCloseAlgorithmProvider(alg, 0);
    if (directoryHandle != INVALID_HANDLE_VALUE) CloseHandle(directoryHandle);
    if (!success) Check(0, "image-test-infrastructure");
    else puts("[완료] image-test-completed");
}

static void Usage(void)
{
    puts("UF_BootProtectionTest: 부팅 영역 판정 모의 시험\n"
         "  --self-test   디스크 쓰기 없이 구간·허용·입력 검증\n"
         "  --image-test  새 일반 파일에서 모의 쓰기와 SHA-256 검증\n"
         "  --all         위 두 시험 실행\n"
         "  --help        도움말\n"
         "  --vhdx-self-test  VHDX 부트 영역 파서 합성 시험 (파일·장치 I/O 없음)\n"
         "  --vhdx-damage FAT32|NTFS --confirm-disposable-vhdx\n"
         "                Hyper-V 게스트 관리자 전용: 새 VHDX의 부트 섹터 실제 손상\n"
         "  --vhdx-protection-test  지원 중단: 이전 별도 디스크 드라이버 시험\n"
         "기존 장치·파일 경로 입력은 지원하지 않습니다. --all에는 실제 손상 시험이 포함되지 않습니다.\n"
         "이 시험은 이관된 파일 미니필터의 실제 부팅 영역 차단 성공을 입증하지 않습니다.");
}

int wmain(int Argc, wchar_t** Argv)
{
    int self, image;
    SetConsoleOutputCP(CP_UTF8);
    if (Argc >= 2 && wcscmp(Argv[1], L"--vhdx-protection-test") == 0) {
        fputs("[지원 중단] --vhdx-protection-test는 배포에서 제외한 별도 디스크 드라이버용 명령입니다.\n"
              "파일 미니필터 이관 시험으로 대체되지 않았으며 파일·장치 I/O 없이 종료합니다.\n", stderr);
        return ERROR_NOT_SUPPORTED;
    }
    if (Argc == 2 && wcscmp(Argv[1], L"--vhdx-self-test") == 0) return UfBootVhdxSelfTest();
    if (Argc == 4 && wcscmp(Argv[1], L"--vhdx-damage") == 0 &&
        wcscmp(Argv[3], L"--confirm-disposable-vhdx") == 0 &&
        (wcscmp(Argv[2], L"FAT32") == 0 || wcscmp(Argv[2], L"NTFS") == 0))
        return UfBootVhdxDamage(wcscmp(Argv[2], L"FAT32") == 0);
    if (Argc == 1 || (Argc == 2 && wcscmp(Argv[1], L"--help") == 0)) { Usage(); return 0; }
    if (Argc != 2) { Usage(); return 2; }
    self = wcscmp(Argv[1], L"--self-test") == 0 || wcscmp(Argv[1], L"--all") == 0;
    image = wcscmp(Argv[1], L"--image-test") == 0 || wcscmp(Argv[1], L"--all") == 0;
    if (!self && !image) { Usage(); return 2; }
    puts("[모의 시험 전용] 실제 디스크·드라이버 보호 성능을 입증하는 시험이 아닙니다.");
    if (self) SelfTest();
    if (image) ImageTest();
    printf("\n결과: 검사 %u개, 실패 %u개. 실제 디스크 쓰기 없음.\n", gChecks, gFailed);
    return gFailed == 0 ? 0 : 1;
}
