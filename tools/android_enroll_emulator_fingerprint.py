#!/usr/bin/env python3
"""Enroll a disposable emulator fingerprint through Android's Settings UI.

This changes the device lock screen; use only on an ephemeral CI emulator.
"""
import subprocess
import time
import xml.etree.ElementTree as ET
from android_select_saf_folder import adb, click, dump


def main():
    adb('shell', 'locksettings', 'set-pin', '1234')
    time.sleep(3)
    adb('shell', 'input', 'keyevent', '224')
    adb('shell', 'input', 'swipe', '160', '550', '160', '100', '300')
    time.sleep(2)
    adb('shell', 'input', 'text', '1234')
    adb('shell', 'input', 'keyevent', '66')
    time.sleep(3)
    adb('shell', 'am', 'start', '-a', 'android.settings.FINGERPRINT_ENROLL')
    history = []
    for _ in range(65):
        time.sleep(1)
        try:
            nodes = list(ET.fromstring(dump()).iter('node'))
        except (subprocess.SubprocessError, ET.ParseError):
            continue
        labels = [(n.get('text') or n.get('content-desc') or '') for n in nodes]
        labels = [x for x in labels if x]
        history.append(labels)
        def find(*words):
            return next((n for n in nodes if (n.get('text') or n.get('content-desc') or '').upper() in words and n.get('enabled') == 'true'), None)
        if any('Re-enter your PIN' in label or 'Enter your PIN' in label for label in labels):
            adb('shell', 'input', 'text', '1234')
            adb('shell', 'input', 'keyevent', '66')
            continue
        done = find('DONE')
        if done:
            click(done)
            print('Enrolled emulator fingerprint')
            return
        button = find('MORE', 'I AGREE', 'AGREE', 'CONTINUE', 'NEXT', 'GOT IT')
        if button:
            click(button)
            continue
        if any('finger' in label.lower() or 'sensor' in label.lower() for label in labels):
            adb('emu', 'finger', 'touch', '1')
            continue
    raise RuntimeError('Could not enroll emulator fingerprint; recent screens: ' + repr(history[-12:]))


if __name__ == '__main__':
    main()
