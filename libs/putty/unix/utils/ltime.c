/*
 * ltime: the current local time, as a value rather than a pointer into a
 * shared static buffer. Upstream PuTTY provides one of these per platform
 * directory; the shared code in source/putty only declares it.
 */

#include <string.h>
#include <time.h>

#include "putty.h"
#include "misc.h"

struct tm ltime(void)
{
    time_t t = time(NULL);
    struct tm tm;

#ifdef HAVE_LOCALTIME_R
    localtime_r(&t, &tm);
#else
    {
        struct tm *tmp = localtime(&t);
        if (tmp)
            tm = *tmp;
        else
            memset(&tm, 0, sizeof(tm));
    }
#endif

    return tm;
}
