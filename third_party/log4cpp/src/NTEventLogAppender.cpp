/*
 * NTEventLogAppender.cpp
 *
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifdef WIN32 // macro is only available on Win32

#include <log4cpp/FactoryParams.hh>
#include <log4cpp/NTEventLogAppender.hh>
#include <memory>
#include <string.h>
#include <string>

#ifdef DEBUG
#include <iostream>
#define PRINT_CONSOLE_DEBUG(stream, msg) stream << msg;
#else
#define PRINT_CONSOLE_DEBUG(stream, msg)
#endif

namespace log4cpp {
    WORD getCategory(Priority::Value priority);
    WORD getType(Priority::Value priority);
    LSTATUS addRegistryInfo(const char* source);

    NTEventLogAppender::NTEventLogAppender(const std::string& name, const std::string& sourceName)
        : AppenderSkeleton(name), _strSourceName(sourceName), _hEventSource(NULL) {
        addRegistryInfo(_strSourceName.c_str());
        open();
    }

    NTEventLogAppender::~NTEventLogAppender() {
        close();
    }

    void NTEventLogAppender::open() {
        _hEventSource = ::RegisterEventSource(NULL, _strSourceName.c_str());
    }

    void NTEventLogAppender::close() {
        if (_hEventSource) {
            ::DeregisterEventSource(_hEventSource);
            _hEventSource = NULL;
        }
    }

    bool NTEventLogAppender::reopen() {
        close();
        open();
        return true;
    }

    bool NTEventLogAppender::requiresLayout() const {
        return false;
    }

    void NTEventLogAppender::setLayout(Layout* layout) {
        return;
    }

    void NTEventLogAppender::_append(const LoggingEvent& event) {
        const char* ps[1];
        ps[0] = event.message.c_str();

        const DWORD messageID = 0x1000;
        ::ReportEvent(_hEventSource, getType(event.priority), getCategory(event.priority), messageID, NULL, 1, 0, ps,
                      NULL);
    }

    /**
     * Convert log4cpp Priority to an EventLog category. Each category is
     * backed by a message resource so that proper category names will
     * be displayed in the NT Event Viewer.
     */
    WORD getCategory(Priority::Value priority) {
        // Priority values map directly to EventLog category values
        return (WORD)((priority / 100) + 1);
    }

    /**
     * Convert log4cpp Priority to an EventLog type. The log4cpp package
     * supports 8 defined priorites, but the NT EventLog only knows
     * 3 event types of interest to us: ERROR, WARNING, and INFO.
     */
    WORD getType(Priority::Value priority) {

        WORD ret_val;

        switch (priority) {
        case Priority::EMERG:
            // FATAL is the same value as EMERG
            //        case Priority::FATAL:
        case Priority::ALERT:
        case Priority::CRIT:
        case Priority::ERROR:
            ret_val = EVENTLOG_ERROR_TYPE;
            break;
        case Priority::WARN:
            ret_val = EVENTLOG_WARNING_TYPE;
            break;
        case Priority::NOTICE:
        case Priority::INFO:
        case Priority::DEBUG:
        case Priority::TRACE:
        default:
            ret_val = EVENTLOG_INFORMATION_TYPE;
            break;
        }
        return ret_val;
    }

    LSTATUS regGetKey(HKEY& hkey, const TCHAR* subkey, DWORD* disposition) {
        LSTATUS res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                                     &hkey, disposition);
        return res;
    }

    LSTATUS regSetString(HKEY hkey, const TCHAR* name, const TCHAR* value) {
        return RegSetValueEx(hkey, name, 0, REG_SZ, (LPBYTE)value, strlen(value) + 1);
    }

    LSTATUS regSetDword(HKEY hkey, const TCHAR* name, DWORD value) {
        return RegSetValueEx(hkey, name, 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    }

    /*
     * Add this source with appropriate configuration keys to the registry.
     */
    LSTATUS addRegistryInfo(const char* source) {
        std::string subkey("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\");
        DWORD disposition;
        HKEY hkey = 0;
        subkey.append(source);

        LSTATUS res = regGetKey(hkey, subkey.c_str(), &disposition);
        if (res == ERROR_SUCCESS) {
            PRINT_CONSOLE_DEBUG(std::cout, "disposition: " << disposition << std::endl)

            if (disposition == REG_CREATED_NEW_KEY) {
                res |= regSetString(hkey, "EventMessageFile", "c:\\usr\\bin\\NTEventLogAppender.dll");
                res |= regSetString(hkey, "CategoryMessageFile", "c:\\usr\\bin\\NTEventLogAppender.dll");
                res |= regSetDword(hkey, "TypesSupported", (DWORD)Priority::priority_count - 2);
                res |= regSetDword(hkey, "CategoryCount", (DWORD)Priority::priority_count - 1);

                PRINT_CONSOLE_DEBUG(std::cout, "regSet* calls cumulative res: " << res << std::endl)
            }
        } else if (res == ERROR_ACCESS_DENIED) {
            PRINT_CONSOLE_DEBUG(std::cerr, "regGetKey err: " << res << "; Admin privileges are required" << std::endl)
        } else {
            PRINT_CONSOLE_DEBUG(std::cerr, "regGetKey err: " << res << std::endl)
        }
        RegCloseKey(hkey);
        return res;
    }

    std::LOG4CPP_UNIQUE_PTR<Appender> create_nt_event_log_appender(const FactoryParams& params) {
        std::string name, source_name;
        params.get_for("nt event log appender").required("name", name)("source_name", source_name);

        return std::LOG4CPP_UNIQUE_PTR<Appender>(new NTEventLogAppender(name, source_name));
    }
} // namespace log4cpp

#endif // WIN32
