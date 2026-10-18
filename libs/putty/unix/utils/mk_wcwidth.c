/*
 * mk_wcwidth: the display width of a wide character.
 *
 * Upstream ships a table-driven implementation for platforms whose libc
 * lacks wcwidth(); the shared code only declares the function. This port
 * builds on POSIX, where the C library already provides the same answer,
 * so delegate to it and fall back to "printable or not" if it fails.
 */

#include <wchar.h>
#include <wctype.h>

#include "putty.h"
#include "misc.h"

int mk_wcwidth(unsigned int ucs)
{
    int width = wcwidth((wchar_t)ucs);
    if (width >= 0)
        return width;

    /* wcwidth() returns -1 for anything it cannot render. Treat a
     * printable character as one column wide, and everything else as a
     * control character that must be stripped. */
    return iswprint((wint_t)ucs) ? 1 : -1;
}
