#!/usr/bin/env python3
"""Choose the smoke fixture using the emulator's real Android DocumentsUI.

This is intentionally for a disposable, English-language emulator only. It
uses accessibility bounds from uiautomator, never hard-coded screen pixels.
"""
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


def adb(*args, timeout=30):
    return subprocess.run(['adb', *args], check=True, capture_output=True, text=True, timeout=timeout).stdout


def dump():
    adb('shell', 'uiautomator', 'dump', '/sdcard/linscp-ui.xml')
    return adb('exec-out', 'cat', '/sdcard/linscp-ui.xml')


def click(node):
    match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds', ''))
    if not match:
        raise RuntimeError('Picker control has invalid bounds')
    x1, y1, x2, y2 = map(int, match.groups())
    adb('shell', 'input', 'tap', str((x1 + x2) // 2), str((y1 + y2) // 2))


def open_directory(node):
    # Focus a card and activate it. Some DocumentsUI builds treat a touch as
    # selection rather than navigation in the tree picker.
    click(node)
    adb('shell', 'input', 'keyevent', 'KEYCODE_ENTER')


def main():
    visited_folder = False
    used = False
    last = ''
    history = []
    for _ in range(45):
        time.sleep(1)
        try:
            last = dump()
            root = ET.fromstring(last)
        except (subprocess.SubprocessError, ET.ParseError):
            continue
        nodes = list(root.iter('node'))
        history.append([(n.get('text') or n.get('content-desc'), n.get('bounds')) for n in nodes if n.get('text') or n.get('content-desc')])
        def matching(*labels):
            return next((n for n in nodes if n.get('text') in labels or n.get('content-desc') in labels), None)
        if used:
            allow = matching('Allow')
            if allow:
                click(allow)
                print('Granted fixture folder via Android DocumentsUI')
                return
        if visited_folder:
            use = matching('Use this folder', 'USE THIS FOLDER')
            if use and use.get('enabled') == 'true':
                click(use)
                used = True
                continue
        folder = matching('LinSCP-Ungranted-Smoke')
        if folder:
            open_directory(folder)
            visited_folder = True
            continue
        docs = matching('Documents')
        if docs:
            open_directory(docs)
            continue
        storage = matching('Internal storage', 'sdk_gphone64_x86_64', 'sdk_gphone64_arm64')
        if storage:
            click(storage)
            continue
        menu = matching('Show roots', 'Open navigation drawer', 'Browse')
        if menu:
            click(menu)
            continue
    print('Could not select test SAF folder; recent screens:', history[-8:], file=sys.stderr)
    raise SystemExit(1)


if __name__ == '__main__':
    main()
