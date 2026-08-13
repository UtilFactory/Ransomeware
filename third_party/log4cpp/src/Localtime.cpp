/*
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#include "Localtime.hh"
#include <log4cpp/Portability.hh>
#include <memory.h>
#include <time.h>

namespace log4cpp {

#if defined(_MSC_VER) && defined(LOG4CPP_HAVE_LOCALTIME_R)
    int localtime_tsafe(const ::time_t* time, ::tm* t) {
        errno_t lt_res = localtime_s(t, time);
        return static_cast<int>(lt_res);
    }
#endif

#if !defined(_MSC_VER) && defined(LOG4CPP_HAVE_LOCALTIME_R)
    int localtime_tsafe(const ::time_t* time, ::tm* t) {
        return (localtime_r(time, t) != NULL ? 0 : -1);
    }
#endif

#if !defined(LOG4CPP_HAVE_LOCALTIME_R)
    int localtime_tsafe(const ::time_t* time, ::tm* t) {
        ::tm* tmp = ::localtime(time);
        if (tmp == NULL) {
            return -1;
        }
        memcpy(t, tmp, sizeof(::tm));
        return 0;
    }
#endif

} // namespace log4cpp
