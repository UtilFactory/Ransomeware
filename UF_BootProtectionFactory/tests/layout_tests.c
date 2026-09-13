#include "../src/layout.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _FIXTURE {
    ULONG Sector;
    ULONGLONG Disk;
    ULONGLONG Start;
    ULONGLONG Count;
    BOOLEAN Gpt;
    BOOLEAN Fat;
    BOOLEAN FailRead;
    ULONG Overread;
    UCHAR Mbr[4096];
    UCHAR Boot[4096];
    UCHAR Backup[4096];
    UCHAR Primary[4096];
    UCHAR Secondary[4096];
    UCHAR Entries[16384];
    UCHAR BackupEntries[16384];
} FIXTURE;
static ULONG checks, failures;
static VOID Put16(PUCHAR p, USHORT n) { p[0] = (UCHAR)n; p[1] = (UCHAR)(n >> 8); }
static VOID Put32(PUCHAR p, ULONG n) { Put16(p, (USHORT)n); Put16(p + 2, (USHORT)(n >> 16)); }
static VOID Put64(PUCHAR p, ULONGLONG n) { Put32(p, (ULONG)n); Put32(p + 4, (ULONG)(n >> 32)); }
static VOID Check(BOOLEAN result, const char* name)
{
    ++checks; if (!result) { ++failures; printf("FAIL %s\n", name); }
}
static VOID Header(PUCHAR p, ULONG sector, ULONGLONG here, ULONGLONG other, ULONGLONG entries, ULONGLONG diskSectors)
{
    memcpy(p, "EFI PART", 8); Put32(p + 8, 0x10000); Put32(p + 12, 92);
    Put64(p + 24, here); Put64(p + 32, other); Put64(p + 40, 2 + 16384 / sector);
    Put64(p + 48, diskSectors - 2 - 16384 / sector); p[56] = 42;
    Put64(p + 72, entries); Put32(p + 80, 128); Put32(p + 84, 128);
}
static VOID FixCrc(FIXTURE* f)
{
    Put32(f->Primary + 88, UfLayoutCrc32(f->Entries, sizeof(f->Entries)));
    Put32(f->Secondary + 88, UfLayoutCrc32(f->BackupEntries, sizeof(f->BackupEntries)));
    Put32(f->Primary + 16, 0); Put32(f->Secondary + 16, 0);
    Put32(f->Primary + 16, UfLayoutCrc32(f->Primary, 92));
    Put32(f->Secondary + 16, UfLayoutCrc32(f->Secondary, 92));
}
static VOID Build(FIXTURE* f, ULONG sector, BOOLEAN fat, BOOLEAN gpt)
{
    static const UCHAR basic[16] = {0xa2,0xa0,0xd0,0xeb,0xe5,0xb9,0x33,0x44,0x87,0xc0,0x68,0xb6,0xb7,0x26,0x99,0xc7};
    ULONGLONG diskSectors;
    memset(f, 0, sizeof(*f)); f->Sector = sector; f->Disk = 64ull * 1024 * 1024;
    diskSectors = f->Disk / sector; f->Start = 1024 * 1024 / sector; f->Count = diskSectors - 2 * f->Start;
    f->Fat = fat; f->Gpt = gpt;
    Put16(f->Mbr + 510, 0xaa55); f->Mbr[450] = gpt ? 0xee : (fat ? 0x0c : 0x07);
    Put32(f->Mbr + 454, (ULONG)(gpt ? 1 : f->Start)); Put32(f->Mbr + 458, (ULONG)(gpt ? diskSectors - 1 : f->Count));
    Put16(f->Boot + 510, 0xaa55); Put16(f->Boot + 11, (USHORT)sector); f->Boot[13] = 1;
    if (fat) {
        memcpy(f->Boot + 82, "FAT32   ", 8); Put16(f->Boot + 14, 32); f->Boot[16] = 2;
        Put32(f->Boot + 32, (ULONG)f->Count); Put32(f->Boot + 36, 100); Put16(f->Boot + 48, 1); Put16(f->Boot + 50, 6);
    } else { memcpy(f->Boot + 3, "NTFS    ", 8); Put64(f->Boot + 40, f->Count - 1); }
    memcpy(f->Backup, f->Boot, sector);
    if (gpt) {
        Header(f->Primary, sector, 1, diskSectors - 1, 2, diskSectors);
        Header(f->Secondary, sector, diskSectors - 1, 1, diskSectors - 1 - 16384 / sector, diskSectors);
        memcpy(f->Entries, basic, 16); f->Entries[16] = 1;
        Put64(f->Entries + 32, f->Start); Put64(f->Entries + 40, f->Start + f->Count - 1);
        memcpy(f->BackupEntries, f->Entries, sizeof(f->Entries)); FixCrc(f);
    }
}
static VOID CopyPiece(PUCHAR target, ULONGLONG offset, ULONG length, ULONGLONG at, ULONG size, const UCHAR* data)
{
    ULONGLONG lo = offset > at ? offset : at;
    ULONGLONG hi = offset + length < at + size ? offset + length : at + size;
    if (lo < hi) memcpy(target + (SIZE_T)(lo - offset), data + (SIZE_T)(lo - at), (SIZE_T)(hi - lo));
}
static NTSTATUS Read(PVOID context, ULONGLONG offset, ULONG length, PVOID buffer)
{
    FIXTURE* f = context;
    if (offset >= f->Disk || length > f->Disk - offset || length > 16384 || offset % f->Sector || length % f->Sector) {
        ++f->Overread; return STATUS_DISK_CORRUPT_ERROR;
    }
    if (f->FailRead) return STATUS_NOT_SUPPORTED;
    memset(buffer, 0, length);
    CopyPiece(buffer, offset, length, 0, f->Sector, f->Mbr);
    CopyPiece(buffer, offset, length, f->Start * f->Sector, f->Sector, f->Boot);
    CopyPiece(buffer, offset, length, (f->Start + (f->Fat ? 6 : f->Count - 1)) * f->Sector, f->Sector, f->Backup);
    if (f->Gpt) {
        CopyPiece(buffer, offset, length, f->Sector, f->Sector, f->Primary);
        CopyPiece(buffer, offset, length, f->Disk - f->Sector, f->Sector, f->Secondary);
        CopyPiece(buffer, offset, length, 2ull * f->Sector, sizeof(f->Entries), f->Entries);
        CopyPiece(buffer, offset, length, f->Disk - f->Sector - sizeof(f->BackupEntries), sizeof(f->BackupEntries), f->BackupEntries);
    }
    return STATUS_SUCCESS;
}
static BOOLEAN Covers(const UF_LAYOUT_RESULT* r, ULONGLONG byte, ULONG kind)
{
    ULONG i;
    for (i = 0; i < r->Count; ++i) if (r->Ranges[i].Kind == kind && byte >= r->Ranges[i].Offset && byte - r->Ranges[i].Offset < r->Ranges[i].Length) return TRUE;
    return FALSE;
}
int main(void)
{
    FIXTURE* f = calloc(1, sizeof(*f));
    UCHAR* scratch = malloc(UF_LAYOUT_SCRATCH + 16);
    UF_LAYOUT_RESULT result;
    ULONG s, fat, gpt, i;
    NTSTATUS status;
    if (!f || !scratch) return 2;
    memset(scratch + UF_LAYOUT_SCRATCH, 0x5a, 16);
    Check(UfLayoutCrc32((const UCHAR*)"123456789", 9) == 0xcbf43926, "CRC32 known vector");
    for (s = 512; s <= 4096; s *= 8) for (fat = 0; fat < 2; ++fat) for (gpt = 0; gpt < 2; ++gpt) {
        Build(f, s, (BOOLEAN)fat, (BOOLEAN)gpt);
        status = UfParseLayout(f->Disk, s, Read, f, scratch, &result);
        Check(NT_SUCCESS(status), "valid FAT32/NTFS MBR/GPT 512/4096");
        Check(Covers(&result, 0, UF_BOOT_KIND_MBR), "MBR coverage");
        Check(Covers(&result, f->Start * s, fat ? UF_BOOT_KIND_FAT32 : UF_BOOT_KIND_NTFS), "primary coverage");
        Check(Covers(&result, (f->Start + (fat ? 6 : f->Count - 1)) * s, fat ? UF_BOOT_KIND_FAT32 : UF_BOOT_KIND_NTFS), "backup coverage");
        Check(result.Count == (gpt ? 3u : 1u) + (fat ? 4u : 2u), "exact range count");
        if (fat) {
            Check(!Covers(&result, (f->Start + 1) * s, UF_BOOT_KIND_FAT32), "primary FSInfo remains writable");
            Check(!Covers(&result, (f->Start + 7) * s, UF_BOOT_KIND_FAT32), "backup FSInfo remains writable");
            Check(Covers(&result, (f->Start + 2) * s, UF_BOOT_KIND_FAT32), "primary extended boot coverage");
            Check(Covers(&result, (f->Start + 8) * s, UF_BOOT_KIND_FAT32), "backup extended boot coverage");
        }
        if (gpt) { Check(Covers(&result, s, UF_BOOT_KIND_GPT), "GPT header coverage"); Check(Covers(&result, f->Disk - 1, UF_BOOT_KIND_GPT), "GPT backup end coverage"); }
        f->Mbr[446] = 0x80;
        Check(!NT_SUCCESS(UfParseLayout(f->Disk, s, Read, f, scratch, &result)), "boot partition rejected");
        f->Mbr[446] = 0; f->Backup[510] = 0;
        Check(!NT_SUCCESS(UfParseLayout(f->Disk, s, Read, f, scratch, &result)), "corrupt backup rejected");
        f->Backup[510] = 0x55; f->Boot[13] = 3;
        Check(!NT_SUCCESS(UfParseLayout(f->Disk, s, Read, f, scratch, &result)), "invalid cluster rejected");
        f->Boot[13] = 1; f->FailRead = TRUE;
        Check(!NT_SUCCESS(UfParseLayout(f->Disk, s, Read, f, scratch, &result)), "I/O failure propagated");
        Check(f->Overread == 0, "reader bounds valid");
    }
    Build(f, 512, FALSE, TRUE); f->Primary[16] ^= 1;
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "GPT header CRC rejected");
    Build(f, 512, FALSE, TRUE); f->BackupEntries[16] ^= 1;
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "GPT backup array mismatch rejected");
    Build(f, 512, FALSE, TRUE); Put32(f->Primary + 80, 0xffffffff); FixCrc(f);
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "GPT entry count overflow rejected");
    Build(f, 512, FALSE, TRUE); Put64(f->Entries + 32, ~0ull); memcpy(f->BackupEntries, f->Entries, sizeof(f->Entries)); FixCrc(f);
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "GPT partition overflow rejected");
    Build(f, 512, FALSE, FALSE); f->Mbr[450] = 0x0f;
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "extended partition unsupported");
    Build(f, 512, FALSE, FALSE); Put32(f->Mbr + 458, 0xffffffff);
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "MBR partition overflow rejected");
    Build(f, 512, TRUE, FALSE); Put16(f->Boot + 50, 31);
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 512, Read, f, scratch, &result)), "FAT backup outside reserved rejected");
    Check(!NT_SUCCESS(UfParseLayout(f->Disk, 1024, Read, f, scratch, &result)), "unsupported sector rejected");
    Check(!NT_SUCCESS(UfParseLayout(f->Disk - 1, 512, Read, f, scratch, &result)), "unaligned disk rejected");
    for (i = 0; i < 16; ++i) Check(scratch[UF_LAYOUT_SCRATCH + i] == 0x5a, "scratch guard retained");
    free(scratch); free(f);
    printf("Boot layout parser: %lu checks, %lu failures\n", checks, failures);
    return failures ? 1 : 0;
}
