#include "layout.h"

static USHORT U16(const UCHAR* p) { return (USHORT)(p[0] | ((USHORT)p[1] << 8)); }
static ULONG U32(const UCHAR* p) { return (ULONG)U16(p) | ((ULONG)U16(p + 2) << 16); }
static ULONGLONG U64(const UCHAR* p) { return (ULONGLONG)U32(p) | ((ULONGLONG)U32(p + 4) << 32); }
static BOOLEAN Equal(const UCHAR* a, const UCHAR* b, ULONG n)
{
    ULONG i;
    for (i = 0; i < n; ++i) if (a[i] != b[i]) return FALSE;
    return TRUE;
}
ULONG UfLayoutCrc32(const UCHAR* Buffer, ULONG Length)
{
    ULONG i, bit, crc = 0xffffffffu;
    for (i = 0; i < Length; ++i) {
        crc ^= Buffer[i];
        for (bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
static NTSTATUS Add(UF_LAYOUT_RESULT* r, ULONGLONG disk, ULONGLONG offset, ULONGLONG length, ULONG kind)
{
    if (!length || offset >= disk || length > disk - offset) return STATUS_DISK_CORRUPT_ERROR;
    if (r->Count >= UF_BOOT_MAX_RANGES) return STATUS_BUFFER_OVERFLOW;
    r->Ranges[r->Count].Offset = offset;
    r->Ranges[r->Count].Length = length;
    r->Ranges[r->Count].Kind = kind;
    r->Ranges[r->Count].Reserved = 0;
    ++r->Count;
    return STATUS_SUCCESS;
}
static NTSTATUS Filesystem(ULONGLONG disk, ULONG sector, ULONGLONG start, ULONGLONG sectors,
    UF_LAYOUT_READ read, PVOID context, PUCHAR scratch, UF_LAYOUT_RESULT* r)
{
    NTSTATUS status;
    ULONGLONG total, backup, bytes;
    ULONG reserved, cluster, fats, fatSectors;
    PUCHAR b = scratch, copy = scratch + 4096;
    static const UCHAR ntfs[8] = { 'N','T','F','S',' ',' ',' ',' ' };
    static const UCHAR fat[8] = { 'F','A','T','3','2',' ',' ',' ' };
    if (!sectors || start >= disk / sector || sectors > disk / sector - start) return STATUS_DISK_CORRUPT_ERROR;
    bytes = sectors * sector;
    status = read(context, start * sector, sector, b);
    if (!NT_SUCCESS(status)) return status;
    if (U16(b + 510) != 0xaa55 || U16(b + 11) != sector) return STATUS_DISK_CORRUPT_ERROR;
    cluster = b[13];
    if (!cluster || cluster > 128 || (cluster & (cluster - 1))) return STATUS_DISK_CORRUPT_ERROR;
    if (Equal(b + 3, ntfs, 8)) {
        total = U64(b + 40);
        /* NTFS BPB는 마지막 섹터 번호를 기록하는 형식도 허용한다. */
        if (sectors < 17 || (total != sectors && total != sectors - 1)) return STATUS_DISK_CORRUPT_ERROR;
        status = read(context, (start + sectors - 1) * sector, sector, copy);
        if (!NT_SUCCESS(status)) return status;
        if (!Equal(b, copy, 84) || U16(copy + 510) != 0xaa55) return STATUS_DISK_CORRUPT_ERROR;
        status = Add(r, disk, start * sector, 16ull * sector, UF_BOOT_KIND_NTFS);
        if (!NT_SUCCESS(status)) return status;
        return Add(r, disk, (start + sectors - 1) * sector, sector, UF_BOOT_KIND_NTFS);
    }
    if (!Equal(b + 82, fat, 8)) return STATUS_NOT_SUPPORTED;
    reserved = U16(b + 14); fats = b[16]; fatSectors = U32(b + 36); total = U32(b + 32);
    backup = U16(b + 50);
    if (U16(b + 17) || U16(b + 19) || U16(b + 22) || !fatSectors || fats != 2 ||
        reserved < 8 || reserved >= sectors || total != sectors || backup == 0 ||
        backup < 3 || backup + 3 > reserved || U16(b + 48) != 1 ||
        (ULONGLONG)fatSectors * fats >= sectors - reserved || bytes < 32ull * 1024 * 1024)
        return STATUS_DISK_CORRUPT_ERROR;
    status = read(context, (start + backup) * sector, sector, copy);
    if (!NT_SUCCESS(status)) return status;
    if (!Equal(b, copy, 90) || U16(copy + 510) != 0xaa55) return STATUS_DISK_CORRUPT_ERROR;
    /* 정상 할당 갱신에 필요한 기본/백업 FSInfo(각 +1)는 보호에서 제외한다. */
    status = Add(r, disk, start * sector, sector, UF_BOOT_KIND_FAT32);
    if (!NT_SUCCESS(status)) return status;
    status = Add(r, disk, (start + 2) * sector, sector, UF_BOOT_KIND_FAT32);
    if (!NT_SUCCESS(status)) return status;
    status = Add(r, disk, (start + backup) * sector, sector, UF_BOOT_KIND_FAT32);
    if (!NT_SUCCESS(status)) return status;
    return Add(r, disk, (start + backup + 2) * sector, sector, UF_BOOT_KIND_FAT32);
}
static NTSTATUS GptHeader(PUCHAR p, ULONG sector, ULONGLONG here, ULONGLONG other)
{
    ULONG size = U32(p + 12), old = U32(p + 16), crc;
    static const UCHAR signature[8] = {'E','F','I',' ','P','A','R','T'};
    if (!Equal(p, signature, 8) || U32(p + 8) != 0x10000 || size < 92 || size > sector ||
        U32(p + 20) || U64(p + 24) != here || U64(p + 32) != other) return STATUS_DISK_CORRUPT_ERROR;
    p[16] = p[17] = p[18] = p[19] = 0;
    crc = UfLayoutCrc32(p, size);
    p[16] = (UCHAR)old; p[17] = (UCHAR)(old >> 8); p[18] = (UCHAR)(old >> 16); p[19] = (UCHAR)(old >> 24);
    return crc == old ? STATUS_SUCCESS : STATUS_DISK_CORRUPT_ERROR;
}
NTSTATUS UfParseLayout(ULONGLONG DiskBytes, ULONG SectorBytes, UF_LAYOUT_READ Read,
    PVOID Context, PUCHAR Scratch, UF_LAYOUT_RESULT* Result)
{
    ULONGLONG sectors, starts[128], lengths[128], first, last, table, backupTable;
    ULONG i, j, count = 0, entries, entryBytes, entrySectors;
    NTSTATUS status;
    PUCHAR mbr = Scratch, primary = Scratch + 8192, secondary = Scratch + 12288;
    PUCHAR entry = Scratch + 16384, backupEntries = Scratch + 32768;
    BOOLEAN gpt = FALSE;
    static const UCHAR basic[16] = {0xa2,0xa0,0xd0,0xeb,0xe5,0xb9,0x33,0x44,0x87,0xc0,0x68,0xb6,0xb7,0x26,0x99,0xc7};
    static const UCHAR zero[16] = {0};
    if (!Read || !Scratch || !Result || (SectorBytes != 512 && SectorBytes != 4096) ||
        DiskBytes % SectorBytes || DiskBytes / SectorBytes < 128) return STATUS_NOT_SUPPORTED;
    RtlZeroMemory(Result, sizeof(*Result));
    sectors = DiskBytes / SectorBytes;
    status = Read(Context, 0, SectorBytes, mbr);
    if (!NT_SUCCESS(status)) return status;
    if (U16(mbr + 510) != 0xaa55) return STATUS_DISK_CORRUPT_ERROR;
    status = Add(Result, DiskBytes, 0, SectorBytes, UF_BOOT_KIND_MBR);
    if (!NT_SUCCESS(status)) return status;
    for (i = 0; i < 4; ++i) {
        PUCHAR p = mbr + 446 + i * 16;
        if (!p[4]) continue;
        if (p[0] != 0) return STATUS_NOT_SUPPORTED;
        if (p[4] == 0xee) { if (gpt || count) return STATUS_NOT_SUPPORTED; gpt = TRUE; continue; }
        if (gpt || (p[4] != 0x07 && p[4] != 0x0b && p[4] != 0x0c)) return STATUS_NOT_SUPPORTED;
        starts[count] = U32(p + 8); lengths[count] = U32(p + 12); ++count;
    }
    if (gpt) {
        status = Read(Context, SectorBytes, SectorBytes, primary);
        if (!NT_SUCCESS(status)) return status;
        status = Read(Context, (sectors - 1) * SectorBytes, SectorBytes, secondary);
        if (!NT_SUCCESS(status)) return status;
        status = GptHeader(primary, SectorBytes, 1, sectors - 1);
        if (!NT_SUCCESS(status)) return status;
        status = GptHeader(secondary, SectorBytes, sectors - 1, 1);
        if (!NT_SUCCESS(status)) return status;
        entries = U32(primary + 80);
        if (!entries || entries > 128 || U32(primary + 84) != 128 ||
            U32(secondary + 80) != entries || U32(secondary + 84) != 128 ||
            !Equal(primary + 40, secondary + 40, 32) || U32(primary + 88) != U32(secondary + 88))
            return STATUS_NOT_SUPPORTED;
        entryBytes = entries * 128; entrySectors = (entryBytes + SectorBytes - 1) / SectorBytes;
        table = U64(primary + 72); backupTable = U64(secondary + 72);
        first = U64(primary + 40); last = U64(primary + 48);
        if (table != 2 || backupTable != sectors - 1 - entrySectors || first < 2 + entrySectors ||
            last < first || last >= backupTable) return STATUS_DISK_CORRUPT_ERROR;
        status = Read(Context, table * SectorBytes, entrySectors * SectorBytes, entry);
        if (!NT_SUCCESS(status)) return status;
        status = Read(Context, backupTable * SectorBytes, entrySectors * SectorBytes, backupEntries);
        if (!NT_SUCCESS(status)) return status;
        if (UfLayoutCrc32(entry, entryBytes) != U32(primary + 88) || !Equal(entry, backupEntries, entryBytes))
            return STATUS_DISK_CORRUPT_ERROR;
        status = Add(Result, DiskBytes, SectorBytes, (1ull + entrySectors) * SectorBytes, UF_BOOT_KIND_GPT);
        if (!NT_SUCCESS(status)) return status;
        status = Add(Result, DiskBytes, backupTable * SectorBytes, (1ull + entrySectors) * SectorBytes, UF_BOOT_KIND_GPT);
        if (!NT_SUCCESS(status)) return status;
        for (i = 0; i < entries; ++i) {
            PUCHAR p = entry + i * 128;
            if (Equal(p, zero, 16)) continue;
            /* 기본 데이터 이외 EFI/MSR/복구/동적 디스크는 이 단계에서 지원하지 않는다. */
            if (!Equal(p, basic, 16) || U64(p + 48)) return STATUS_NOT_SUPPORTED;
            starts[count] = U64(p + 32);
            if (starts[count] < first || starts[count] > last || U64(p + 40) < starts[count] || U64(p + 40) > last)
                return STATUS_DISK_CORRUPT_ERROR;
            lengths[count] = U64(p + 40) - starts[count] + 1; ++count;
        }
    }
    if (!count) return STATUS_NOT_SUPPORTED;
    for (i = 0; i < count; ++i) {
        if (!starts[i] || starts[i] >= sectors || !lengths[i] || lengths[i] > sectors - starts[i])
            return STATUS_DISK_CORRUPT_ERROR;
        for (j = 0; j < i; ++j)
            if (starts[i] < starts[j] + lengths[j] && starts[j] < starts[i] + lengths[i]) return STATUS_DISK_CORRUPT_ERROR;
        status = Filesystem(DiskBytes, SectorBytes, starts[i], lengths[i], Read, Context, Scratch, Result);
        if (!NT_SUCCESS(status)) return status;
    }
    return STATUS_SUCCESS;
}
