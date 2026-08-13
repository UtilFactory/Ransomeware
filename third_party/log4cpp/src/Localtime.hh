/*
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef _LOG4CPP_LOCALTIME_HH
#define _LOG4CPP_LOCALTIME_HH

#include <time.h>

namespace log4cpp {
    /**
     * Thread safe replacement for \c localtime() function.
     * Wraps \c localtime_r on Linux and \c localtime_s on Windows.
     * @return error code or 0 for success.
     */
    int localtime_tsafe(const ::time_t* time, ::tm* t);
}

#endif
