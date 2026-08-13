/*
 * Priority.cpp
 *
 * Copyright 2000, LifeLine Networks BV (www.lifeline.nl). All rights reserved.
 * Copyright 2000, Bastiaan Bakker. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#include "PortabilityImpl.hh"
#include <cstdlib>
#include <log4cpp/Priority.hh>

namespace log4cpp {

    namespace {
        const std::string priority_notset_name = "NOTSET";
        const std::string priority_names[] = {"FATAL",  "ALERT", "CRIT",  "ERROR", "WARN",
                                              "NOTICE", "INFO",  "DEBUG", "TRACE", priority_notset_name,
                                              "UNKNOWN"};

        const std::string* names() {
            return priority_names;
        }
    } // namespace

    const int log4cpp::Priority::MESSAGE_SIZE = 8;
    const std::size_t Priority::priority_count = sizeof(priority_names) / sizeof(priority_names[0]);

    const std::string& Priority::getPriorityName(int priority) LOG4CPP_NOTHROW {

        priority++;
        priority /= 100;
        return ((priority < 0) || (priority > priority_count - 1)) ? priority_notset_name : names()[priority];
    }

    Priority::Value Priority::getPriorityValue(const std::string& priorityName) {
        Priority::Value value = -1;

        for (unsigned int i = 0; i < priority_count; i++) {
            if (priorityName == names()[i]) {
                value = i * 100;
                break;
            }
        }

        if (value == -1) {
            if (priorityName == "EMERG") {
                value = 0;
            } else {
                char* endPointer;
                value = std::strtoul(priorityName.c_str(), &endPointer, 10);
                if (*endPointer != 0) {
                    throw std::invalid_argument(std::string("unknown priority name: '") + priorityName + "'");
                }
            }
        }

        return value;
    }
} // namespace log4cpp
