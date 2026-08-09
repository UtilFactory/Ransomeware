#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string>

#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>

#include "../include/uf_log.h"

namespace {

#ifndef UF_LOG_FILE_NAME
#define UF_LOG_FILE_NAME L"uf_fltwarp.log"
#endif

SRWLOCK gLogLock = SRWLOCK_INIT;
log4cpp::Category* gCategory = nullptr;

std::string UfUtf8FromWide(const std::wstring& Text)
{
    if (Text.empty()) {
        return std::string();
    }
    int length = WideCharToMultiByte(
        CP_UTF8, 0, Text.c_str(), static_cast<int>(Text.size()),
        nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return std::string();
    }
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, Text.c_str(), static_cast<int>(Text.size()),
        &result[0], length, nullptr, nullptr);
    return result;
}

std::wstring UfLogDirectory()
{
    HMODULE module = nullptr;
    wchar_t modulePath[MAX_PATH] = {};
    DWORD length = 0;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&UfLogInitialize), &module)) {
        return L"logs";
    }
    length = GetModuleFileNameW(module, modulePath, ARRAYSIZE(modulePath));
    if (length == 0 || length >= ARRAYSIZE(modulePath)) {
        return L"logs";
    }
    std::wstring path(modulePath, length);
    size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return L"logs";
    }
    path.resize(separator + 1);
    path.append(L"logs");
    CreateDirectoryW(path.c_str(), nullptr);
    return path;
}

log4cpp::Priority::Value UfLogPriority(int Level)
{
    switch (Level) {
    case UfLogDebug:
        return log4cpp::Priority::DEBUG;
    case UfLogWarn:
        return log4cpp::Priority::WARN;
    case UfLogError:
        return log4cpp::Priority::ERROR;
    default:
        return log4cpp::Priority::INFO;
    }
}

void UfLogInitializeLocked()
{
    if (gCategory != nullptr) {
        return;
    }
    try {
        std::wstring directory = UfLogDirectory();
        std::wstring filePath = directory + L"\\" + UF_LOG_FILE_NAME;
        std::string utf8Path = UfUtf8FromWide(filePath);
        log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
        layout->setConversionPattern("%d [%p] %m%n");
        log4cpp::FileAppender* appender = new log4cpp::FileAppender(
            "uf_fltwarp_file", utf8Path, true);
        appender->setLayout(layout);
        gCategory = &log4cpp::Category::getInstance("uf_fltwarp");
        gCategory->setPriority(log4cpp::Priority::DEBUG);
        gCategory->addAppender(appender);
    } catch (...) {
        gCategory = nullptr;
    }
}

}

extern "C" void UfLogInitialize(void)
{
    AcquireSRWLockExclusive(&gLogLock);
    UfLogInitializeLocked();
    ReleaseSRWLockExclusive(&gLogLock);
}

extern "C" void UfLogShutdown(void)
{
    AcquireSRWLockExclusive(&gLogLock);
    if (gCategory != nullptr) {
        gCategory->removeAllAppenders();
        log4cpp::Category::shutdownForced();
        gCategory = nullptr;
    }
    ReleaseSRWLockExclusive(&gLogLock);
}

extern "C" void UfLogWrite(int Level, const char* Message)
{
    if (Message == nullptr) {
        return;
    }
    AcquireSRWLockExclusive(&gLogLock);
    UfLogInitializeLocked();
    if (gCategory != nullptr) {
        gCategory->log(UfLogPriority(Level), "%s", Message);
    }
    ReleaseSRWLockExclusive(&gLogLock);
}

extern "C" void UfLogWriteFormat(int Level, const char* Format, ...)
{
    char message[1024] = {};
    va_list arguments;
    if (Format == nullptr) {
        return;
    }
    va_start(arguments, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, arguments);
    va_end(arguments);
    UfLogWrite(Level, message);
}
