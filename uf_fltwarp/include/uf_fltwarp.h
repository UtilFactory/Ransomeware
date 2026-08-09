#pragma once

#include <stddef.h>
#include <wchar.h>
#include "../../UF_FileFilterFactory/include/uf_filefilter_protocol.h"

#if defined(UF_FLTWARP_EXPORTS)
#define UF_FLTWARP_API __declspec(dllexport)
#else
#define UF_FLTWARP_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UF_FLT_PATH_INPUT {
    unsigned long Mode;
    const wchar_t* DosPath;
} UF_FLT_PATH_INPUT;

typedef struct _UF_FLT_POLICY_INPUT {
    unsigned long PathRuleCount;
    const UF_FLT_PATH_INPUT* PathRules;
    unsigned long MonitorExceptionCount;
    const wchar_t* const* MonitorExceptions;
    unsigned long AllowedImageCount;
    const wchar_t* const* AllowedImages;
} UF_FLT_POLICY_INPUT;

typedef struct _UF_FLT_PATH_INPUT_V2 {
    unsigned long RuleId;
    unsigned long Mode;
    const wchar_t* DosPath;
} UF_FLT_PATH_INPUT_V2;

typedef struct _UF_FLT_PROTECTED_PROCESS_INPUT {
    unsigned long RuleId;
    unsigned long FolderRuleId;
    unsigned long SignerRuleId;
    PROTECTED_FOLDER_ACCESS Access;
    // 서명 확인과 전체 경로·파일 이름 비교 방식은 플래그로 지정합니다.
    unsigned short Reserved;
    const wchar_t* DosImagePath;
} UF_FLT_PROTECTED_PROCESS_INPUT;

typedef struct _UF_FLT_SIGNER_INPUT {
    unsigned long RuleId;
    unsigned long MatchType;
    const wchar_t* ThumbprintSha256Hex;
    const wchar_t* IssuerSha256Hex;
    const wchar_t* SerialNumberHex;
    const wchar_t* DisplayCompany;
} UF_FLT_SIGNER_INPUT;

typedef struct _UF_FLT_POLICY_INPUT_V2 {
    unsigned long long PolicyGeneration;
    unsigned long PathRuleCount;
    const UF_FLT_PATH_INPUT_V2* PathRules;
    unsigned long MonitorExceptionCount;
    const wchar_t* const* MonitorExceptions;
    unsigned long ProtectedProcessRuleCount;
    const UF_FLT_PROTECTED_PROCESS_INPUT* ProtectedProcesses;
    unsigned long SignerRuleCount;
    const UF_FLT_SIGNER_INPUT* Signers;
    unsigned long OnlineRevocationEnabled;
    unsigned long RevocationTimeoutMilliseconds;
    unsigned long RevocationTimeoutAction;
    unsigned long TerminateOnRevoked;
} UF_FLT_POLICY_INPUT_V2;

typedef struct _UF_FLT_SIGNER_IDENTITY {
    unsigned long Size;
    unsigned long Trusted;
    unsigned long SerialLengthBytes;
    unsigned long Reserved;
    unsigned char ThumbprintSha256[UF_CERT_SHA256_BYTES];
    unsigned char IssuerSha256[UF_CERT_SHA256_BYTES];
    unsigned char SerialNumber[UF_CERT_SERIAL_BYTES];
    wchar_t Subject[UF_MAX_IMAGE_CHARS];
} UF_FLT_SIGNER_IDENTITY;

typedef struct _UF_FLT_PROCESS_TRUST_INPUT {
    unsigned long long PolicyGeneration;
    unsigned long long ProcessCreateTime;
    unsigned long ProcessId;
    unsigned long ProcessRuleId;
    PROTECTED_FOLDER_ACCESS Access;
    unsigned short Decision;
    unsigned long Temporary;
    const UF_FLT_SIGNER_IDENTITY* SignerIdentity;
} UF_FLT_PROCESS_TRUST_INPUT;

typedef void (__stdcall* UF_FLT_EVENT_CALLBACK)(
    const UF_FILE_EVENT* Event,
    void* Context);

typedef void (__stdcall* UF_FLT_EVENT_CALLBACK_V2)(
    const UF_FILE_EVENT_V2* Event,
    void* Context);

UF_FLTWARP_API unsigned long __stdcall UfFltInitialize(void);
UF_FLTWARP_API void __stdcall UfFltShutdown(void);
UF_FLTWARP_API unsigned long __stdcall UfFltConnect(void);
UF_FLTWARP_API void __stdcall UfFltDisconnect(void);
UF_FLTWARP_API int __stdcall UfFltIsConnected(void);
UF_FLTWARP_API unsigned long __stdcall UfFltReplacePolicy(
    const UF_FLT_POLICY_INPUT* Policy);
UF_FLTWARP_API unsigned long __stdcall UfFltReplacePolicyV2(
    const UF_FLT_POLICY_INPUT_V2* Policy);
UF_FLTWARP_API unsigned long __stdcall UfFltClearPolicy(void);
UF_FLTWARP_API unsigned long __stdcall UfFltQueryState(UF_STATE_REPLY* State);
UF_FLTWARP_API unsigned long __stdcall UfFltQueryStateV2(UF_STATE_REPLY_V2* State);
UF_FLTWARP_API unsigned long __stdcall UfFltStartEventReceiver(
    UF_FLT_EVENT_CALLBACK Callback,
    void* Context);
UF_FLTWARP_API unsigned long __stdcall UfFltStartEventReceiverV2(
    UF_FLT_EVENT_CALLBACK_V2 Callback,
    void* Context);
UF_FLTWARP_API void __stdcall UfFltStopEventReceiver(void);
UF_FLTWARP_API unsigned long __stdcall UfFltDosPathToNtPath(
    const wchar_t* DosPath,
    wchar_t* NtPath,
    unsigned long NtPathChars);
UF_FLTWARP_API unsigned long __stdcall UfFltGetImageSignerIdentity(
    const wchar_t* ImagePath,
    int OnlineRevocation,
    UF_FLT_SIGNER_IDENTITY* Identity);
UF_FLTWARP_API unsigned long __stdcall UfFltGetImageSignerIdentityWithTimeout(
    const wchar_t* ImagePath,
    int OnlineRevocation,
    unsigned long TimeoutMilliseconds,
    UF_FLT_SIGNER_IDENTITY* Identity);
UF_FLTWARP_API unsigned long __stdcall UfFltSetProcessTrust(
    const UF_FLT_PROCESS_TRUST_INPUT* Trust);
UF_FLTWARP_API unsigned long __stdcall UfFltGetErrorMessage(
    unsigned long ErrorCode,
    wchar_t* Message,
    unsigned long MessageChars);

#ifdef __cplusplus
}
#endif
