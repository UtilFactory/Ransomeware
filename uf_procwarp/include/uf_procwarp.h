#pragma once

#include <windows.h>
#include <winioctl.h>
#include "../../UF_ProcessFilterFactory/include/uf_processfilter_protocol.h"

#if defined(UF_PROCWARP_EXPORTS)
#define UF_PROCWARP_API __declspec(dllexport)
#else
#define UF_PROCWARP_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UF_PROC_RULE_INPUT {
    unsigned long RuleId;
    unsigned long MatchMode;
    const wchar_t* Image;
} UF_PROC_RULE_INPUT;

typedef struct _UF_PROC_POLICY_INPUT {
    unsigned long RuleCount;
    const UF_PROC_RULE_INPUT* Rules;
} UF_PROC_POLICY_INPUT;

typedef struct _UF_PROC_RULE_INPUT_V2 {
    unsigned long RuleId;
    const wchar_t* ProcessName;
    const wchar_t* ProcessPath;
    unsigned short IsSign;
    unsigned short IsCmpFullPath;
} UF_PROC_RULE_INPUT_V2;

typedef struct _UF_PROC_POLICY_INPUT_V2 {
    unsigned long PolicyCount;
    const UF_PROC_RULE_INPUT_V2* Policies;
} UF_PROC_POLICY_INPUT_V2;

typedef void (__stdcall* UF_PROC_EVENT_CALLBACK)(
    const UF_PROC_EVENT* Event,
    void* Context);

UF_PROCWARP_API unsigned long __stdcall UfProcInitialize(void);
UF_PROCWARP_API void __stdcall UfProcShutdown(void);
UF_PROCWARP_API unsigned long __stdcall UfProcConnect(void);
UF_PROCWARP_API void __stdcall UfProcDisconnect(void);
UF_PROCWARP_API int __stdcall UfProcIsConnected(void);
UF_PROCWARP_API unsigned long __stdcall UfProcReplacePolicy(
    const UF_PROC_POLICY_INPUT* Policy);
UF_PROCWARP_API unsigned long __stdcall UfProcReplacePolicyV2(
    const UF_PROC_POLICY_INPUT_V2* Policy);
UF_PROCWARP_API unsigned long __stdcall UfProcAddPolicyV2(
    const UF_PROC_POLICY_INPUT_V2* Policy);
UF_PROCWARP_API unsigned long __stdcall UfProcRemovePolicyNames(
    const wchar_t* const* ProcessNames,
    unsigned long ProcessNameCount);
UF_PROCWARP_API unsigned long __stdcall UfProcClearPolicy(void);
UF_PROCWARP_API unsigned long __stdcall UfProcQueryState(
    UF_PROC_STATE_REPLY* State);
UF_PROCWARP_API unsigned long __stdcall UfProcStartEventReceiver(
    UF_PROC_EVENT_CALLBACK Callback,
    void* Context);
UF_PROCWARP_API void __stdcall UfProcStopEventReceiver(void);
UF_PROCWARP_API unsigned long __stdcall UfProcGetErrorMessage(
    unsigned long ErrorCode,
    wchar_t* Message,
    unsigned long MessageChars);
UF_PROCWARP_API unsigned long __stdcall UfProcGetPolicyCallStage(void);

#ifdef __cplusplus
}
#endif
