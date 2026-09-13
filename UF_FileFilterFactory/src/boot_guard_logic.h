#pragma once

/* 커널 I/O 없이 경계·장치 이름·바이트 비교를 시험하는 공통 판정 함수이다. */
#define UF_BOOT_GUARD_BYTES 2048UL

static __inline ULONG
UfBootProtectedWriteLength(LONGLONG Offset, ULONG Length)
{
    ULONG remaining;
    if (Offset < 0 || Offset >= UF_BOOT_GUARD_BYTES || Length == 0) {
        return 0;
    }
    remaining = UF_BOOT_GUARD_BYTES - (ULONG)Offset;
    return Length < remaining ? Length : remaining;
}

static __inline WCHAR
UfBootFoldAscii(WCHAR Character)
{
    return Character >= L'A' && Character <= L'Z'
        ? (WCHAR)(Character + (L'a' - L'A')) : Character;
}

static __inline int
UfBootMatchLiteral(const WCHAR* Name, ULONG Length, ULONG* Position, const WCHAR* Literal)
{
    ULONG index = *Position;
    while (*Literal != L'\0') {
        if (index >= Length || UfBootFoldAscii(Name[index]) != UfBootFoldAscii(*Literal)) {
            return 0;
        }
        ++index;
        ++Literal;
    }
    *Position = index;
    return 1;
}

static __inline int
UfBootConsumeDigits(const WCHAR* Name, ULONG Length, ULONG* Position)
{
    ULONG start = *Position;
    while (*Position < Length && Name[*Position] >= L'0' && Name[*Position] <= L'9') {
        ++*Position;
    }
    return *Position != start;
}

static __inline int
UfBootIsDeviceIdentity(const WCHAR* Name, ULONG LengthChars)
{
    ULONG position = 0;
    ULONG suffix;
    if (Name == NULL || !UfBootMatchLiteral(Name, LengthChars, &position, L"\\Device\\Harddisk")) {
        return 0;
    }
    suffix = position;
    if (UfBootMatchLiteral(Name, LengthChars, &position, L"Volume")) {
        return UfBootConsumeDigits(Name, LengthChars, &position) && position == LengthChars;
    }
    position = suffix;
    return UfBootConsumeDigits(Name, LengthChars, &position) &&
        UfBootMatchLiteral(Name, LengthChars, &position, L"\\DR") &&
        UfBootConsumeDigits(Name, LengthChars, &position) && position == LengthChars;
}

static __inline int
UfBootIsRawTarget(int VolumeOpen, int EmptyFileName, int DeviceVerified)
{
    return (VolumeOpen || EmptyFileName) && DeviceVerified;
}

static __inline int
UfBootPrefixDiffers(const unsigned char* Current, const unsigned char* Incoming, ULONG Length)
{
    ULONG index;
    if (Length > UF_BOOT_GUARD_BYTES || Current == NULL || Incoming == NULL) {
        return -1;
    }
    for (index = 0; index < Length; ++index) {
        if (Current[index] != Incoming[index]) {
            return 1;
        }
    }
    return 0;
}

static __inline ULONG
UfBootAlignedReadLength(ULONG SectorSize)
{
    if (SectorSize < 512 || SectorSize > 65536 || (SectorSize & (SectorSize - 1)) != 0) {
        return 0;
    }
    return (UF_BOOT_GUARD_BYTES + SectorSize - 1) & ~(SectorSize - 1);
}
