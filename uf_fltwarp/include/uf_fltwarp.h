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

typedef void (__stdcall* UF_FLT_EVENT_CALLBACK)(
    const UF_FILE_EVENT* Event,
    void* Context);

UF_FLTWARP_API unsigned long __stdcall UfFltInitialize(void);
UF_FLTWARP_API void __stdcall UfFltShutdown(void);
UF_FLTWARP_API unsigned long __stdcall UfFltConnect(void);
UF_FLTWARP_API void __stdcall UfFltDisconnect(void);
UF_FLTWARP_API int __stdcall UfFltIsConnected(void);
UF_FLTWARP_API unsigned long __stdcall UfFltReplacePolicy(
    const UF_FLT_POLICY_INPUT* Policy);
UF_FLTWARP_API unsigned long __stdcall UfFltClearPolicy(void);
UF_FLTWARP_API unsigned long __stdcall UfFltQueryState(UF_STATE_REPLY* State);
UF_FLTWARP_API unsigned long __stdcall UfFltStartEventReceiver(
    UF_FLT_EVENT_CALLBACK Callback,
    void* Context);
UF_FLTWARP_API void __stdcall UfFltStopEventReceiver(void);
UF_FLTWARP_API unsigned long __stdcall UfFltDosPathToNtPath(
    const wchar_t* DosPath,
    wchar_t* NtPath,
    unsigned long NtPathChars);
UF_FLTWARP_API unsigned long __stdcall UfFltGetErrorMessage(
    unsigned long ErrorCode,
    wchar_t* Message,
    unsigned long MessageChars);

#ifdef __cplusplus
}
#endif
