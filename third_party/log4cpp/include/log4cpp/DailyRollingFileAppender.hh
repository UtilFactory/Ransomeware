/*
 * DailyRollingFileAppender.hh
 *
 * Copyright 2015, Alexander Perepelkin. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef _LOG4CPP_DAILYROLLINGFILEAPPENDER_HH
#define _LOG4CPP_DAILYROLLINGFILEAPPENDER_HH

#include <ctime>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/Portability.hh>
#include <stdarg.h>
#include <string>

namespace log4cpp {

    /**
     * DailyRollingFileAppender is a FileAppender that rolls over the logfile when a log event is recorded on a
     * different day than the previous log event.
     * SupportsDailyRollingFileAppender: more detailed documentation, added safety checks to implementation, refine
     * tests automatic cleanup of old log files based on a configurable retention period. Log files older than (\c
     * _maxDaysToKeep) are removed. The default value is \c maxDaysToKeepDefault.
     *
     * @since 1.1.2
     */
    class LOG4CPP_EXPORT DailyRollingFileAppender : public FileAppender {
      public:
        DailyRollingFileAppender(const std::string& name, const std::string& fileName,
                                 unsigned int maxDaysToKeep = maxDaysToKeepDefault, bool append = true,
                                 mode_t mode = 00644);

        /**
         * Set \c _maxDaysToKeep.
         * @param maxDaysToKeep if not positive, then \c maxDaysToKeepDefault is used instead.
         */
        virtual void setMaxDaysToKeep(unsigned int maxDaysToKeep);
        virtual unsigned int getMaxDaysToKeep() const;

        virtual void rollOver();

        static unsigned int maxDaysToKeepDefault;

      protected:
        virtual void _append(const LoggingEvent& event);

        /**
         * Maximum number of days to keep log files on disk. Files older than this limit are deleted during rollover.
         */
        unsigned int _maxDaysToKeep;

        /**
         * last log's file creation time (or last modification if appender just created)
         */
        struct tm _logsTime;
    };
} // namespace log4cpp

#endif // _LOG4CPP_DAILYROLLINGFILEAPPENDER_HH
