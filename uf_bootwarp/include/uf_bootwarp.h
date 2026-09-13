#pragma once
#include <windows.h>
#include <winioctl.h>
#include "../../UF_BootProtectionFactory/include/uf_boot_protocol.h"
#ifdef UF_BOOTWARP_EXPORTS
#define UF_BOOT_API __declspec(dllexport)
#else
#define UF_BOOT_API __declspec(dllimport)
#endif
#ifdef __cplusplus
extern "C" {
#endif
UF_BOOT_API DWORD __stdcall UfBootQueryDevices(UF_BOOT_DEVICE_LIST* Reply);
UF_BOOT_API DWORD __stdcall UfBootSetProtection(const UF_BOOT_SET_REQUEST* Request, UF_BOOT_DEVICE_INFO* Reply);
UF_BOOT_API DWORD __stdcall UfBootReadEvents(UF_BOOT_EVENT_BATCH* Reply);
#ifdef __cplusplus
}
#endif
