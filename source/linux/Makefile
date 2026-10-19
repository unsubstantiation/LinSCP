# Native POSIX (Debian/Linux) build of LinSCP.
#
# This builds the console client `linscp` for Linux out of the LinSCP
# front end in this directory, with SSH, SFTP and SCP served by libssh
# (and hashes by the OpenSSL crypto library libssh itself links).
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

# libssh (SSH/SFTP/SCP transport), OpenSSL libcrypto (hashes and PPK key
# handling), and libargon2 (encrypted PPK v3 keys). pkg-config finds them
# where the distro (or a local prefix) put them; flags can be overridden.
SSH_CFLAGS ?= $(shell pkg-config --cflags libssh libcrypto 2>/dev/null)
SSH_LIBS ?= $(shell pkg-config --libs libssh libcrypto 2>/dev/null || echo -lssh -lcrypto)
ARGON2_CFLAGS ?= $(shell pkg-config --cflags libargon2 2>/dev/null)
ARGON2_LIBS ?= $(shell pkg-config --libs libargon2 2>/dev/null || echo -largon2)
CFLAGS_APP += $(ARGON2_CFLAGS)
CXXFLAGS_APP += $(ARGON2_CFLAGS)

# -MMD -MP: write a .d file next to every object, so that a change to a
# header rebuilds the sources that include it.
DEPFLAGS := -MMD -MP

CFLAGS_APP := -std=gnu99 $(OPT) -g $(WARN) -Wno-unused-parameter $(DEPFLAGS) \
	-D_FILE_OFFSET_BITS=64 -DNO_GSSAPI $(SSH_CFLAGS) -pthread $(CFLAGS)

CXXFLAGS_APP := -std=gnu++17 $(OPT) -g $(WARN) -pthread $(DEPFLAGS) \
	-D_FILE_OFFSET_BITS=64 -DNO_GSSAPI $(SSH_CFLAGS) -I. $(CXXFLAGS)

# Front end (this directory).
APP_SRCS := \
	Session.cpp \
	SessionStore.cpp \
	ListingParse.cpp \
	FtpClient.cpp \
	ScpClient.cpp \
	TransferPresets.cpp \
	SftpClient.cpp \
	HashUtil.c \
	ProtocolClient.cpp \
	S3SigV4.cpp \
	S3Client.cpp \
	SshTunnel.cpp \
	SshKeys.cpp \
	PpkKey.cpp \
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

PREFIX ?= /usr
DESTDIR ?=

.PHONY: all clean check check-live check-conversion check-wayland install

all: $(BINDIR)/linscp

$(BINDIR)/linscp: $(APP_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -o $@ $(APP_OBJS) $(LDFLAGS) $(SSH_LIBS) $(ARGON2_LIBS) $(LIBS)

# Catalogs are compiled into Texts.cpp; regenerate the table with
# tools/compile_translations.py after editing locales/*.json.
$(OBJDIR)/linux/Texts.o: Translations.inc

$(OBJDIR)/linux/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -c $< -o $@

$(OBJDIR)/linux/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_APP) -I. -c $< -o $@

$(OBJDIR)/linux/tests/%.o: tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -Itests -c $< -o $@

$(BINDIR)/unittest: $(TEST_OBJS) $(APP_LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_APP) -Itests -o $@ $(TEST_OBJS) $(APP_LIB_OBJS) $(LDFLAGS) $(SSH_LIBS) $(ARGON2_LIBS) $(LIBS)

check: $(BINDIR)/unittest
	$(BINDIR)/unittest
	$(PYTHON) $(TOP)/tools/check_platform_conversion.py
	$(PYTHON) $(TOP)/tools/tests/test_platform_conversion.py
	$(PYTHON) $(TOP)/tools/check_wayland_compatibility.py
	$(PYTHON) $(TOP)/tools/tests/test_wayland_compatibility.py

# The guard that keeps this a Linux-only client: it reads the sources
# and refuses a Windows construct, a file of another platform, an
# installer that disagrees with the others, and an error message that
# contradicts the template it is filled into.
check-conversion:
	$(PYTHON) $(TOP)/tools/check_platform_conversion.py
	$(PYTHON) $(TOP)/tools/tests/test_platform_conversion.py

# The other half of 'runs on Linux': a Wayland desktop, where an
# application that only asks for $DISPLAY finds no display at all. It
# refuses a display-server decision that reads one variable, a
# terminal that may not be able to draw on this compositor, a helper
# program only one display server answers, a desktop entry nobody can
# act on, and the two detections of the session disagreeing.
check-wayland:
	$(PYTHON) $(TOP)/tools/check_wayland_compatibility.py
	$(PYTHON) $(TOP)/tools/tests/test_wayland_compatibility.py

# Transfers against the servers in tests/, which take seconds rather than
# milliseconds: ScriptTest is server-free, LiveSftpTest skips itself without
# paramiko, LiveScpTest starts a throwaway sshd of its own and skips itself
# without sshd/ssh-keygen, LiveS3Test is standard-library-only (botocore is an
# optional extra one test skips without), LiveCurlTest uses optional pyftpdlib/
# pyOpenSSL when available, the GUI search test uses a fake session, and the
# PowerShell harness always runs its static checks while its live Pester run
# skips itself without pwsh.
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
	$(PYTHON) ../../source/gui/tests/TerminalTest.py
	$(PYTHON) ../../automation/test_psmodule.py $(BINDIR)/linscp

# Pull in the generated dependencies, if this is not the first build.
-include $(APP_OBJS:.o=.d) $(TEST_OBJS:.o=.d)

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
	install -m 0644 $(shell find $(TOP)/source/gui/web -maxdepth 1 -type f) $(DESTDIR)$(PREFIX)/share/linscp/gui/web/
	install -d $(DESTDIR)$(PREFIX)/share/linscp/gui/web/vendor
	install -m 0644 $(TOP)/source/gui/web/vendor/* $(DESTDIR)$(PREFIX)/share/linscp/gui/web/vendor/
	install -m 0644 $(TOP)/debian/linscp.desktop $(DESTDIR)$(PREFIX)/share/applications/linscp.desktop
	install -m 0644 $(TOP)/debian/linscp.png $(DESTDIR)$(PREFIX)/share/pixmaps/linscp.png
	install -m 0644 $(TOP)/debian/linscp.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/linscp.svg
	install -m 0644 $(TOP)/docs/linscp.1 $(DESTDIR)$(PREFIX)/share/man/man1/linscp.1
	install -m 0644 $(TOP)/automation/LinSCP.psm1 $(DESTDIR)$(PREFIX)/share/linscp/automation/

clean:
	rm -rf $(BUILD)
