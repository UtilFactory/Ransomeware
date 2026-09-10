#pragma once
#include <stdint.h>

/* 디스크 I/O와 분리한 내부 판정 모델이며 드라이버 통신 ABI가 아니다. */
#define UF_BOOT_RANGE_LIMIT 64u

typedef struct UF_BOOT_RANGE {
    uint32_t Id;
    uint64_t Offset;
    uint64_t Length;
} UF_BOOT_RANGE;

typedef struct UF_BOOT_RANGE_POLICY {
    uint64_t DeviceToken;
    uint64_t Generation;
    uint64_t DiskBytes;
    uint32_t SectorBytes;
    uint32_t RangeCount;
    UF_BOOT_RANGE Ranges[UF_BOOT_RANGE_LIMIT];
} UF_BOOT_RANGE_POLICY;

typedef struct UF_BOOT_WRITE_REQUEST {
    uint64_t DeviceToken;
    uint64_t Generation;
    uint64_t Offset;
    uint64_t Length;
    uint64_t ProcessId;
    uint64_t ProcessCreated;
    uint32_t RequestorKnown;
} UF_BOOT_WRITE_REQUEST;

typedef struct UF_BOOT_MAINTENANCE_PERMIT {
    uint64_t DeviceToken;
    uint64_t Generation;
    uint64_t ProcessId;
    uint64_t ProcessCreated;
    uint64_t Offset;
    uint64_t Length;
    uint64_t ExpiresAt;
    uint32_t RangeId;
} UF_BOOT_MAINTENANCE_PERMIT;

typedef enum UF_BOOT_VERDICT {
    UfBootInvalid = 0,
    UfBootNotCovered,
    UfBootAllow,
    UfBootBlock
} UF_BOOT_VERDICT;

typedef enum UF_BOOT_REASON {
    UfBootInvalidPolicy = 0,
    UfBootInvalidRequest,
    UfBootOtherDevice,
    UfBootStaleGeneration,
    UfBootOutsideProtectedRange,
    UfBootUnauthorizedWrite,
    UfBootMaintenanceAllowed
} UF_BOOT_REASON;

typedef struct UF_BOOT_DECISION {
    UF_BOOT_VERDICT Verdict;
    UF_BOOT_REASON Reason;
    uint32_t RangeId;
} UF_BOOT_DECISION;

int UfBootValidateRangePolicy(const UF_BOOT_RANGE_POLICY* Policy);
UF_BOOT_DECISION UfBootEvaluateWrite(
    const UF_BOOT_RANGE_POLICY* Policy,
    const UF_BOOT_WRITE_REQUEST* Request,
    const UF_BOOT_MAINTENANCE_PERMIT* Permit,
    uint64_t Now);
