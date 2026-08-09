#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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
    wchar_t processPath[MAX_PATH] = {};
    DWORD length = 0;
    // DLL이 로드된 경로가 아니라 호스트 프로세스 실행 경로를 사용한다.
    length = GetModuleFileNameW(nullptr, processPath, ARRAYSIZE(processPath));
    if (length == 0 || length >= ARRAYSIZE(processPath)) {
        return L"logs";
    }
    std::wstring path(processPath, length);
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

const char* UfLogLevelName(int Level)
{
    switch (Level) {
    case UfLogDebug:
        return "DEBUG";
    case UfLogWarn:
        return "WARN";
    case UfLogError:
        return "ERROR";
    default:
        return "INFO";
    }
}

void UfLogWriteFile(int Level, const char* Message)
{
    std::wstring filePath = UfLogDirectory() + L"\\" + UF_LOG_FILE_NAME;
    HANDLE file = CreateFileW(
        filePath.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        OutputDebugStringA(Message);
        OutputDebugStringA("\n");
        return;
    }

    SYSTEMTIME time;
    GetLocalTime(&time);
    char line[1280] = {};
    int lineLength = _snprintf_s(
        line, sizeof(line), _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u [%s] %s\r\n",
        time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
        UfLogLevelName(Level), Message);
    if (lineLength > 0) {
        DWORD written = 0;
        WriteFile(file, line, (DWORD)lineLength, &written, nullptr);
    }
    CloseHandle(file);
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

extern "C" void UfLogBootstrapWrite(const char* Message)
{
    if (Message == nullptr) {
        return;
    }

    std::wstring filePath = UfLogDirectory() + L"\\uf_fltwarp.bootstrap.log";
    HANDLE file = CreateFileW(
        filePath.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        OutputDebugStringA(Message);
        OutputDebugStringA("\n");
        return;
    }

    SYSTEMTIME time;
    GetLocalTime(&time);
    char prefix[96] = {};
    int prefixLength = _snprintf_s(
        prefix, sizeof(prefix), _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u [%lu] ",
        time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
        GetCurrentThreadId());
    if (prefixLength > 0) {
        DWORD written = 0;
        WriteFile(file, prefix, (DWORD)prefixLength, &written, nullptr);
    }

    DWORD messageLength = (DWORD)strlen(Message);
    DWORD written = 0;
    WriteFile(file, Message, messageLength, &written, nullptr);
    WriteFile(file, "\r\n", 2, &written, nullptr);
    CloseHandle(file);
}

extern "C" void UfLogInitialize(void)
{
    UfLogBootstrapWrite("UfLogInitialize 진입");
    AcquireSRWLockExclusive(&gLogLock);
    UfLogBootstrapWrite("UfLogInitialize 잠금 획득");
    UfLogInitializeLocked();
    UfLogBootstrapWrite("UfLogInitialize 내부 초기화 완료");
    ReleaseSRWLockExclusive(&gLogLock);
    UfLogBootstrapWrite("UfLogInitialize 종료");
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
    // UI 호스트에서 log4cpp 기록이 프로세스 초기화를 방해하지 않도록
    // Win32 파일 기록을 기본 경로로 사용한다. log4cpp 초기화와 라이브러리
    // 연결은 유지하여 기존 구성요소 호환성을 보존한다.
    UfLogWriteFile(Level, Message);
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
