/*
 * X11 forwarding is not part of this client: it transfers files, it does
 * not forward a display. Upstream puts these entry points in x11fwd.c and
 * the per-platform X11 files, none of which are built here. The SSH code
 * still refers to them, so provide versions that report "not available"
 * rather than pulling an entire X11 implementation into a file transfer
 * tool.
 */

#include <stddef.h>

#include "putty.h"
#include "ssh.h"

int x11_authcmp(void *av, void *bv)
{
    (void)av;
    (void)bv;
    return 0;
}

struct X11Display *x11_setup_display(const char *display, Conf *conf,
                                     char **error_msg)
{
    (void)display;
    (void)conf;
    if (error_msg)
        *error_msg = dupstr("X11 forwarding is not supported by this client");
    return NULL;
}

void x11_free_display(struct X11Display *disp)
{
    (void)disp;
}

struct X11FakeAuth *x11_invent_fake_auth(tree234 *t, int authtype)
{
    (void)t;
    (void)authtype;
    return NULL;
}

void x11_free_fake_auth(struct X11FakeAuth *auth)
{
    (void)auth;
}

Channel *x11_new_channel(tree234 *authtree, SshChannel *c,
                         const char *peeraddr, int peerport,
                         bool connection_sharing_possible)
{
    (void)authtree;
    (void)c;
    (void)peeraddr;
    (void)peerport;
    (void)connection_sharing_possible;
    return NULL;
}

void *x11_make_greeting(int endian, int protomajor, int protominor,
                        int auth_proto, const void *auth_data, int auth_len,
                        const char *peer_ip, int peer_port, int *outlen)
{
    (void)endian;
    (void)protomajor;
    (void)protominor;
    (void)auth_proto;
    (void)auth_data;
    (void)auth_len;
    (void)peer_ip;
    (void)peer_port;
    if (outlen)
        *outlen = 0;
    return NULL;
}

int x11_identify_auth_proto(ptrlen protoname)
{
    (void)protoname;
    return -1;
}

void *x11_dehexify(ptrlen hex, int *outlen)
{
    (void)hex;
    if (outlen)
        *outlen = 0;
    return NULL;
}
