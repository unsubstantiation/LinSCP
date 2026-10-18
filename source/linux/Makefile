# Native POSIX (Debian/Linux) build of LinSCP.
#
# This builds the console client `linscp` for Linux out of:
#
#   * the platform-neutral PuTTY core (source/putty, listed in putty-core.mk),
#   * a POSIX platform layer vendored from upstream PuTTY 0.85
#     (libs/putty/unix, libs/putty/charset),
#   * the upstream PuTTY SFTP client library (libs/putty/ssh/sftp.c),
#   * the LinSCP front end in this directory.
#
# Usage:
#   make -C source/linux            # builds build/linscp
#   make -C source/linux check      # runs the unit tests
#   make -C source/linux check-live # script and live-server suites
#   make -C source/linux clean
#
# 'make install' lays out the same tree as 'cmake --install' and the
# Debian package: the client in bin/, the graphical client's modules and
# command templates under share/linscp/gui/, the PowerShell module under
# share/linscp/automation/, the manual page, the desktop entry and the
# icons. Nothing else is installed: this client has no library, no
# header and no other platform's surface.
#
# See ../../docs/debian.md for the Debian package build.

ifneq ($(shell uname -s),Linux)
$(error LinSCP supports Linux only; this Makefile requires the Linux platform layer)
endif

TOP := ../..
BUILD ?= build

# No built-in rules: we build every object explicitly below.
MAKEFLAGS += -r
OBJDIR := $(BUILD)/obj
BINDIR := $(BUILD)

CC ?= cc
CXX ?= c++
AR ?= ar

# The Python 3 interpreter the checkers and the script suites run with.
PYTHON ?= python3

OPT ?= -O2
WARN ?= -Wall

# -DFORK_BUILD               : build the PuTTY core in "embedded library" mode,
#                              as the upstream core expects.
# -DPLATFORM_HAS_SMEMCLR     : the core provides smemclr().
# -DNO_GSSAPI                : no GSSAPI/Kerberos support in this build.
# -DHAVE_...                 : C library features available on Linux.
# -DHAVE_AES_NI=0 etc.       : use the portable crypto implementations in
#                              source/putty/crypto so the build does not depend
#                              on architecture-specific intrinsics flags.
PUTTY_DEFS := \
	-DFORK_BUILD \
	-DMPEXT \
	-DPLATFORM_HAS_SMEMCLR \
	-DNO_GSSAPI \
	-DHAVE_AES_NI=0 \
	-DHAVE_SHA_NI=0 \
	-DHAVE_CLMUL=0 \
	-DHAVE_NEON_CRYPTO=0 \
	-DHAVE_NEON_PMULL=0 \
	-DHAVE_NEON_SHA512=0 \
	-DHAVE_SYS_TYPES_H=1 \
	-DHAVE_SYS_STAT_H=1 \
	-DHAVE_SYS_TIME_H=1 \
	-DHAVE_SYS_SELECT_H=1 \
	-DHAVE_SYS_SOCKET_H=1 \
	-DHAVE_SYS_IOCTL_H=1 \
	-DHAVE_SYS_UN_H=1 \
	-DHAVE_SYS_UIO_H=1 \
	-DHAVE_NETDB_H=1 \
	-DHAVE_NETINET_IN_H=1 \
	-DHAVE_ARPA_INET_H=1 \
	-DHAVE_POLL_H=1 \
	-DHAVE_FCNTL_H=1 \
	-DHAVE_TERMIOS_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DHAVE_PWD_H=1 \
	-DHAVE_GLOB_H=1 \
	-DHAVE_POLL=1 \
	-DHAVE_CLOCK_GETTIME=1 \
	-DHAVE_CLOCK_MONOTONIC=1 \
	-DHAVE_SETPWENT=1 \
	-DHAVE_ENDPWENT=1 \
	-DHAVE_FUTIMES=1 \
	-DHAVE_GETADDRINFO=1 \
	-DHAVE_UTIMES=1 \
	-DHAVE_SYSCTLBYNAME=0 \
	-DHAVE_SO_PEERCRED=1 \
	-DHAVE_GETAUXVAL=1 \
	-DHAVE_SYS_AUXV_H=1 \
	-DHAVE_ASM_HWCAP_H=1 \
	-DHAVE_ELF_AUX_INFO=0 \
	-DHAVE_SYS_SYSCTL_H=0

PUTTY_INCLUDES := \
	-I$(TOP)/source/putty \
	-I$(TOP)/libs/putty/unix \
	-I$(TOP)/libs/putty \
	-I$(TOP)/libs/putty/charset

# -MMD -MP: write a .d file next to every object, so that a change to a
# header rebuilds the sources that include it.
DEPFLAGS := -MMD -MP

CFLAGS_PUTTY := -std=gnu99 $(OPT) -g $(WARN) -Wno-unused-parameter $(DEPFLAGS) \
	-D_FILE_OFFSET_BITS=64 $(PUTTY_DEFS) $(PUTTY_INCLUDES) -pthread $(CFLAGS)

# The front end includes the core headers, so it must be compiled with the
# same $(PUTTY_DEFS) as the core itself (MPEXT in particular changes the
# signatures the core exposes).
CXXFLAGS_APP := -std=gnu++17 $(OPT) -g $(WARN) -pthread $(DEPFLAGS) \
	-D_FILE_OFFSET_BITS=64 $(PUTTY_DEFS) \
	-I. -I$(TOP)/source/putty -I$(TOP)/libs/putty/unix \
	-I$(TOP)/libs/putty -I$(TOP)/libs/putty/charset $(CXXFLAGS)

include putty-core.mk

# Core sources that the POSIX platform layer replaces. The core's own copy
# would clash with the one in libs/putty/unix, so it is left out. The real
# implementation comes from libs/putty/unix. Keeping both would give
# duplicate symbols at link time:
#
#   ssh/nosharing.c       -> libs/putty/unix/sharing.c
#                            (platform_ssh_share[_cleanup])
PUTTY_CORE_REPLACED := \
	$(TOP)/source/putty/ssh/nosharing.c

PUTTY_CORE_SRCS := $(filter-out $(PUTTY_CORE_REPLACED),$(PUTTY_CORE_SRCS))

# POSIX platform layer, vendored from upstream PuTTY 0.85.
PUTTY_VEND_SRCS := \
	$(wildcard $(TOP)/libs/putty/unix/*.c) \
	$(wildcard $(TOP)/libs/putty/unix/utils/*.c) \
	$(wildcard $(TOP)/libs/putty/unix/stubs/*.c) \
	$(wildcard $(TOP)/libs/putty/utils/*.c) \
	$(filter-out $(TOP)/libs/putty/charset/enum.c,$(wildcard $(TOP)/libs/putty/charset/*.c)) \
	$(TOP)/libs/putty/ssh/sftp.c \
	$(TOP)/libs/putty/ssh/sftpcommon.c \
	$(TOP)/libs/putty/psftpcommon.c \
	$(TOP)/libs/putty/pinger.c \
	$(TOP)/libs/putty/timing.c

PUTTY_ALL_SRCS := $(PUTTY_CORE_SRCS) $(PUTTY_VEND_SRCS)

# Object file names mirror the source tree, rooted at the repository top.
putty_obj = $(OBJDIR)/$(patsubst $(TOP)/%.c,%.o,$(1))

PUTTY_OBJS := $(foreach s,$(PUTTY_ALL_SRCS),$(call putty_obj,$(s)))

# Front end (this directory). SftpClient.c is C on purpose, see its header.
APP_SRCS := \
	Session.cpp \
	SessionStore.cpp \
	ListingParse.cpp \
	FtpClient.cpp \
	ScpClient.cpp \
	TransferPresets.cpp \
	SftpClient.c \
	HashUtil.c \
	ProtocolClient.cpp \
	S3SigV4.cpp \
	S3Client.cpp \
	SshTunnel.cpp \
	PuttyGlue.cpp \
	Script.cpp \
	ScriptParams.cpp \
	SyncPlanner.cpp \
	Editor.cpp \
	Console.cpp \
	LocalFs.cpp \
	PathUtil.cpp \
	Platform.cpp \
	Texts.cpp \
	TextMode.cpp \
	main.cpp

app_obj = $(OBJDIR)/linux/$(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(1)))
APP_OBJS := $(foreach s,$(APP_SRCS),$(call app_obj,$(s)))
MAIN_OBJ := $(OBJDIR)/linux/main.o
# Everything but main(), so that the unit tests can use the front end.
APP_LIB_OBJS := $(filter-out $(MAIN_OBJ),$(APP_OBJS))
TEST_OBJS := $(OBJDIR)/linux/tests/UnitTest.o
SBSCGEN := $(BINDIR)/sbcsgen

PUTTY_LIB := $(BUILD)/libputty.a

PREFIX ?= /usr
DESTDIR ?=

.PHONY: all clean check check-live check-conversion install

all: $(BINDIR)/linscp

$(PUTTY_LIB): $(PUTTY_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BINDIR)/linscp: $(APP_OBJS) $(PUTTY_LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -o $@ $(APP_OBJS) $(PUTTY_LIB) $(LDFLAGS) $(LIBS)

$(OBJDIR)/source/%.o: $(TOP)/source/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_PUTTY) -c $< -o $@

# be_list.c is compiled once per application and takes its name from the
# command line. SSH/SERIAL/OTHERBACKENDS already come from defs.h under
# FORK_BUILD, so only APPNAME is missing here.
$(OBJDIR)/source/putty/be_list.o: CFLAGS_PUTTY += -DAPPNAME=LinSCP

$(OBJDIR)/libs/%.o: $(TOP)/libs/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_PUTTY) -c $< -o $@

# Catalogs are compiled into Texts.cpp; regenerate the table with
# tools/compile_translations.py after editing locales/*.json.
$(OBJDIR)/linux/Texts.o: Translations.inc

$(OBJDIR)/linux/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -c $< -o $@

$(OBJDIR)/linux/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_PUTTY) -I. -c $< -o $@

$(OBJDIR)/linux/tests/%.o: tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -Itests -c $< -o $@

$(BINDIR)/unittest: $(TEST_OBJS) $(APP_LIB_OBJS) $(PUTTY_LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -Itests -o $@ $(TEST_OBJS) $(APP_LIB_OBJS) $(PUTTY_LIB) $(LDFLAGS) $(LIBS)

# Build the charset table maintainer tool only for checks, not for the client.
$(SBSCGEN): $(TOP)/libs/putty/charset/sbcsgen.cpp
	@mkdir -p $(dir $@)
	$(CXX) -std=gnu++17 $(OPT) -g $(WARN) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

check: $(BINDIR)/unittest $(SBSCGEN)
	$(BINDIR)/unittest
	$(SBSCGEN) --check --input $(TOP)/libs/putty/charset/sbcs.dat \
		--expected $(TOP)/libs/putty/charset/sbcsdat.c
	$(PYTHON) $(TOP)/tools/check_platform_conversion.py
	$(PYTHON) $(TOP)/tools/tests/test_platform_conversion.py

# The guard that keeps this a Linux-only client: it reads the sources
# and refuses a Windows construct, a file of another platform, an
# installer that disagrees with the others, and an error message that
# contradicts the template it is filled into.
check-conversion:
	$(PYTHON) $(TOP)/tools/check_platform_conversion.py
	$(PYTHON) $(TOP)/tools/tests/test_platform_conversion.py

# Transfers against the servers in tests/, which take seconds rather than
# milliseconds: ScriptTest is server-free, LiveSftpTest skips itself without
# paramiko, LiveScpTest starts a throwaway sshd of its own and skips itself
# without sshd/ssh-keygen, LiveS3Test is standard-library-only (botocore is an
# optional extra one test skips without), LiveCurlTest uses optional pyftpdlib/
# pyOpenSSL when available, and the GUI search test uses a fake session.
check-live: $(BINDIR)/linscp
	$(PYTHON) tests/ScriptTest.py $(BINDIR)/linscp
	$(PYTHON) tests/LiveSftpTest.py $(BINDIR)/linscp
	$(PYTHON) tests/LiveScpTest.py $(BINDIR)/linscp
	$(PYTHON) tests/LiveS3Test.py $(BINDIR)/linscp
	$(PYTHON) tests/LiveDavTest.py $(BINDIR)/linscp
	$(PYTHON) tests/LiveCurlTest.py $(BINDIR)/linscp
	$(PYTHON) ../../source/gui/tests/RemoteSearchTest.py
	$(PYTHON) ../../source/gui/tests/LocalEditorTest.py
	$(PYTHON) ../../source/gui/tests/BrowserUploadTest.py
	$(PYTHON) ../../source/gui/tests/DesktopUriTest.py
	$(PYTHON) ../../source/gui/tests/SecurityTest.py

# Pull in the generated dependencies, if this is not the first build.
-include $(PUTTY_OBJS:.o=.d) $(APP_OBJS:.o=.d) $(TEST_OBJS:.o=.d)

install: $(BINDIR)/linscp
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -d $(DESTDIR)$(PREFIX)/share/applications
	install -d $(DESTDIR)$(PREFIX)/share/pixmaps
	install -d $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps
	install -d $(DESTDIR)$(PREFIX)/share/linscp/gui/web
	install -d $(DESTDIR)$(PREFIX)/share/linscp/automation
	install -m 0755 $(BINDIR)/linscp $(DESTDIR)$(PREFIX)/bin/linscp
	install -m 0755 $(TOP)/source/gui/linscp-gui $(DESTDIR)$(PREFIX)/bin/linscp-gui
	install -m 0644 $(TOP)/source/gui/linscp_gui.py $(TOP)/source/gui/linscp_crypto.py \
		$(DESTDIR)$(PREFIX)/share/linscp/gui/
	install -m 0644 $(TOP)/source/gui/explorer-commands.json \
		$(DESTDIR)$(PREFIX)/share/linscp/gui/
	install -m 0644 $(TOP)/source/gui/web/* $(DESTDIR)$(PREFIX)/share/linscp/gui/web/
	install -m 0644 $(TOP)/debian/linscp.desktop $(DESTDIR)$(PREFIX)/share/applications/linscp.desktop
	install -m 0644 $(TOP)/debian/linscp.png $(DESTDIR)$(PREFIX)/share/pixmaps/linscp.png
	install -m 0644 $(TOP)/debian/linscp.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/linscp.svg
	install -m 0644 $(TOP)/docs/linscp.1 $(DESTDIR)$(PREFIX)/share/man/man1/linscp.1
	install -m 0644 $(TOP)/automation/LinSCP.psm1 $(DESTDIR)$(PREFIX)/share/linscp/automation/

clean:
	rm -rf $(BUILD)
