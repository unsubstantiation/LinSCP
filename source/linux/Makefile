# LinSCP - Makefile wrapper over the pure-Rust Cargo workspace (Phase 6).
#
# The production engine now lives in crates/* (pure-Rust) and ui/; this
# Makefile is retained as a convenience wrapper so that `make -C source/linux`
# and the Debian source package's expectations keep working, and so CI can
# exercise evidence lines via `cargo test` under the hood.
#
# Previous releases built the C++17 client (source/linux/*.cpp + libssh) here;
# that implementation has been retired - the engine now lives in crates/*
# (linscp-proto, linscp-engine, linscp-platform) and the UI in ui/.
#
# Usage:
#   make -C source/linux            # cargo build --release --workspace (+ ui)
#   make -C source/linux check      # cargo test + repo hygiene
#   make -C source/linux check-live # live Python suites vs target/release/linscp
#   make -C source/linux clean      # cargo clean

TOP := ../..
BUILD ?= $(TOP)/target
PYTHON ?= python3
CARGO ?= cargo
NPM ?= npm

.PHONY: all clean check check-live check-conversion check-wayland install

all:
	$(CARGO) build --release --workspace
	@if [ -d $(TOP)/ui ]; then $(NPM) --prefix $(TOP)/ui install --no-audit --no-fund && $(NPM) --prefix $(TOP)/ui run build; fi

# Rust unit + integration tests replace the former linscp-unittest C++ binary.
check:
	$(CARGO) test --workspace --all-targets
	$(PYTHON) $(TOP)/tools/check_platform_conversion.py
	$(PYTHON) $(TOP)/tools/tests/test_platform_conversion.py
	$(PYTHON) $(TOP)/tools/check_wayland_compatibility.py
	$(PYTHON) $(TOP)/tools/tests/test_wayland_compatibility.py

check-conversion:
	$(PYTHON) $(TOP)/tools/check_platform_conversion.py
	$(PYTHON) $(TOP)/tools/tests/test_platform_conversion.py

check-wayland:
	$(PYTHON) $(TOP)/tools/check_wayland_compatibility.py
	$(PYTHON) $(TOP)/tools/tests/test_wayland_compatibility.py

# Live suites drive target/release/linscp (Rust). Keep evidence lines:
#   evidence: suite=... ran=.. skipped=.. failed=..
# The BIN is the Rust binary, not the old source/linux/build/linscp.
BIN ?= $(TOP)/target/release/linscp

check-live: all
	$(PYTHON) tests/ScriptTest.py $(BIN)
	$(PYTHON) tests/LiveSftpTest.py $(BIN)
	$(PYTHON) tests/LiveTunnelTest.py $(BIN)
	$(PYTHON) tests/LiveScpTest.py $(BIN)
	$(PYTHON) tests/LiveS3Test.py $(BIN)
	$(PYTHON) tests/LiveDavTest.py $(BIN)
	$(PYTHON) tests/LiveCurlTest.py $(BIN)
	$(PYTHON) ../../source/gui/tests/RemoteSearchTest.py
	$(PYTHON) ../../source/gui/tests/LocalEditorTest.py
	$(PYTHON) ../../source/gui/tests/BrowserUploadTest.py
	$(PYTHON) ../../source/gui/tests/DesktopUriTest.py
	$(PYTHON) ../../source/gui/tests/ShellIntegrationTest.py
	$(PYTHON) ../../source/gui/tests/SecurityTest.py
	$(PYTHON) ../../source/gui/tests/LocalWorkspaceTest.py
	$(PYTHON) ../../source/gui/tests/TerminalTest.py
	$(PYTHON) ../../automation/test_psmodule.py $(BIN)
	$(PYTHON) ../../automation/test_dotnet.py $(BIN)

install: all
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/share/man/man1
	install -d $(DESTDIR)/usr/share/applications
	install -d $(DESTDIR)/usr/share/pixmaps
	install -d $(DESTDIR)/usr/share/icons/hicolor/scalable/apps
	install -d $(DESTDIR)/usr/share/linscp/automation
	install -d $(DESTDIR)/usr/share/linscp/dotnet
	install -m 0755 $(TOP)/target/release/linscp $(DESTDIR)/usr/bin/linscp
	install -m 0755 $(TOP)/target/release/linscp-gui $(DESTDIR)/usr/bin/linscp-gui
	install -m 0644 $(TOP)/automation/LinSCP.psm1 $(DESTDIR)/usr/share/linscp/automation/
	install -m 0644 $(TOP)/automation/dotnet/LinSCP/LinSCP.csproj \
		$(TOP)/automation/dotnet/LinSCP/Session.cs \
		$(TOP)/automation/dotnet/LinSCP/LinSCPCompat.cs \
		$(DESTDIR)/usr/share/linscp/dotnet/
	install -m 0644 $(TOP)/debian/linscp.desktop $(DESTDIR)/usr/share/applications/linscp.desktop
	install -m 0644 $(TOP)/debian/linscp.png $(DESTDIR)/usr/share/pixmaps/linscp.png
	install -m 0644 $(TOP)/debian/linscp.svg $(DESTDIR)/usr/share/icons/hicolor/scalable/apps/linscp.svg
	install -m 0644 $(TOP)/docs/linscp.1 $(DESTDIR)/usr/share/man/man1/linscp.1

clean:
	$(CARGO) clean
	rm -rf $(BUILD)
