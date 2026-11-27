# Convenience wrapper for the native Tauri desktop application.
TOP := ../..
CARGO ?= cargo
NPM ?= npm
PYTHON ?= python3
PREFIX ?= /usr
.PHONY: all check clean install
all:
	cd $(TOP) && $(NPM) --prefix ui ci --no-audit --no-fund
	cd $(TOP) && $(NPM) --prefix ui run build
	cd $(TOP) && $(CARGO) build --release -p linscp-tauri --features native-shell
check:
	cd $(TOP) && $(CARGO) test --workspace --all-targets
	cd $(TOP) && $(NPM) --prefix ui test
install: all
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(PREFIX)/share/applications" "$(DESTDIR)$(PREFIX)/share/pixmaps" "$(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps"
	install -m 0755 "$(TOP)/target/release/linscp-gui" "$(DESTDIR)$(PREFIX)/bin/linscp-gui"
	$(PYTHON) "$(TOP)/tools/install_desktop_entry.py" --prefix "$(PREFIX)" --destdir "$(DESTDIR)" --template "$(TOP)/debian/linscp.desktop"
	install -m 0644 "$(TOP)/debian/linscp.png" "$(DESTDIR)$(PREFIX)/share/pixmaps/linscp.png"
	install -m 0644 "$(TOP)/debian/linscp.svg" "$(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/linscp.svg"
clean:
	cd $(TOP) && $(CARGO) clean
