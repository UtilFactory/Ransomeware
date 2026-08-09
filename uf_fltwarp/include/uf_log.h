#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum UF_LOG_LEVEL {
    UfLogDebug = 0,
    UfLogInfo = 1,
    UfLogWarn = 2,
    UfLogError = 3
};

void UfLogInitialize(void);
void UfLogShutdown(void);
void UfLogWrite(int Level, const char* Message);
void UfLogWriteFormat(int Level, const char* Format, ...);

#ifdef __cplusplus
}
#endif
