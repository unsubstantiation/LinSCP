# Convenience wrapper for the native Tauri desktop application.
TOP := ../..
CARGO ?= cargo
NPM ?= npm
PYTHON ?= python3
.PHONY: all check clean install
all:
	cd $(TOP) && $(NPM) --prefix ui ci --no-audit --no-fund
	cd $(TOP) && $(NPM) --prefix ui run build
	cd $(TOP) && $(CARGO) build --release -p linscp-tauri --features native-shell
check:
	cd $(TOP) && $(CARGO) test --workspace --all-targets
	cd $(TOP) && $(NPM) --prefix ui test
install: all
	install -d $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/applications $(DESTDIR)/usr/share/pixmaps $(DESTDIR)/usr/share/icons/hicolor/scalable/apps
	install -m 0755 $(TOP)/target/release/linscp-gui $(DESTDIR)/usr/bin/linscp-gui
	install -m 0644 $(TOP)/debian/linscp.desktop $(DESTDIR)/usr/share/applications/linscp.desktop
	install -m 0644 $(TOP)/debian/linscp.png $(DESTDIR)/usr/share/pixmaps/linscp.png
	install -m 0644 $(TOP)/debian/linscp.svg $(DESTDIR)/usr/share/icons/hicolor/scalable/apps/linscp.svg
clean:
	cd $(TOP) && $(CARGO) clean
