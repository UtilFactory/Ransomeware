#include "../include/uf_boot_range.h"
#include <stddef.h>

static int ValidSpan(uint64_t Offset, uint64_t Length, uint64_t Capacity)
{
    /* 덧셈 전에 뺄셈으로 검사하여 오버플로를 피한다. */
    return Length != 0 && Offset < Capacity && Length <= Capacity - Offset;
}

int UfBootValidateRangePolicy(const UF_BOOT_RANGE_POLICY* Policy)
{
    uint32_t i, j;
    if (Policy == NULL || Policy->DeviceToken == 0 || Policy->Generation == 0 ||
        (Policy->SectorBytes != 512 && Policy->SectorBytes != 4096) ||
        Policy->DiskBytes == 0 || Policy->DiskBytes % Policy->SectorBytes != 0 ||
        Policy->RangeCount == 0 || Policy->RangeCount > UF_BOOT_RANGE_LIMIT) {
        return 0;
    }
    for (i = 0; i < Policy->RangeCount; ++i) {
        const UF_BOOT_RANGE* range = &Policy->Ranges[i];
        if (range->Id == 0 || !ValidSpan(range->Offset, range->Length, Policy->DiskBytes) ||
            range->Offset % Policy->SectorBytes != 0 ||
            range->Length % Policy->SectorBytes != 0) {
            return 0;
        }
        /* 정책은 위치순이며 중복·겹침을 허용하지 않는다. 인접한 영역은 가능하다. */
        if (i != 0 && Policy->Ranges[i - 1].Offset + Policy->Ranges[i - 1].Length > range->Offset) {
            return 0;
        }
        for (j = 0; j < i; ++j) {
            if (Policy->Ranges[j].Id == range->Id) {
                return 0;
            }
        }
    }
    return 1;
}

static int PermitMatches(const UF_BOOT_RANGE_POLICY* Policy,
    const UF_BOOT_WRITE_REQUEST* Request, const UF_BOOT_MAINTENANCE_PERMIT* Permit,
    const UF_BOOT_RANGE* Range, uint64_t Now)
{
    if (Permit == NULL || Request->RequestorKnown != 1 || Request->ProcessId == 0 ||
        Request->ProcessCreated == 0 || Permit->ExpiresAt <= Now ||
        Permit->DeviceToken != Policy->DeviceToken || Permit->Generation != Policy->Generation ||
        Permit->ProcessId != Request->ProcessId || Permit->ProcessCreated != Request->ProcessCreated ||
        Permit->RangeId != Range->Id ||
        !ValidSpan(Permit->Offset, Permit->Length, Policy->DiskBytes)) {
        return 0;
    }
    /* 단일 영역에 한정한 허용이 다른 보호 영역까지 확장되지 않게 한다. */
    if (Permit->Offset < Range->Offset ||
        Permit->Offset + Permit->Length > Range->Offset + Range->Length) {
        return 0;
    }
    return Request->Offset >= Permit->Offset &&
        Request->Offset + Request->Length <= Permit->Offset + Permit->Length;
}

UF_BOOT_DECISION UfBootEvaluateWrite(const UF_BOOT_RANGE_POLICY* Policy,
    const UF_BOOT_WRITE_REQUEST* Request, const UF_BOOT_MAINTENANCE_PERMIT* Permit,
    uint64_t Now)
{
    UF_BOOT_DECISION result = { UfBootInvalid, UfBootInvalidPolicy, 0 };
    uint32_t i;
    if (!UfBootValidateRangePolicy(Policy)) {
        return result;
    }
    result.Reason = UfBootInvalidRequest;
    if (Request == NULL || Request->RequestorKnown > 1) {
        return result;
    }
    if (Request->DeviceToken != Policy->DeviceToken) {
        result.Verdict = UfBootNotCovered;
        result.Reason = UfBootOtherDevice;
        return result;
    }
    if (Request->Generation != Policy->Generation) {
        result.Reason = UfBootStaleGeneration;
        return result;
    }
    if (!ValidSpan(Request->Offset, Request->Length, Policy->DiskBytes)) {
        return result;
    }
    result.Verdict = UfBootAllow;
    result.Reason = UfBootOutsideProtectedRange;
    for (i = 0; i < Policy->RangeCount; ++i) {
        const UF_BOOT_RANGE* range = &Policy->Ranges[i];
        if (Request->Offset < range->Offset + range->Length &&
            range->Offset < Request->Offset + Request->Length) {
            result.RangeId = range->Id;
            if (!PermitMatches(Policy, Request, Permit, range, Now)) {
                result.Verdict = UfBootBlock;
                result.Reason = UfBootUnauthorizedWrite;
                return result;
            }
            result.Reason = UfBootMaintenanceAllowed;
        }
    }
    return result;
}
