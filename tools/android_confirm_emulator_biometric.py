#!/usr/bin/env python3
"""Wait for the native prompt and send one disposable emulator fingerprint."""
import argparse
import subprocess
import time
import xml.etree.ElementTree as ET
from android_select_saf_folder import adb, dump


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('fingerprint', choices=['1', '2'])
    args = parser.parse_args()
    history = []
    for _ in range(30):
        try:
            nodes = list(ET.fromstring(dump()).iter('node'))
        except (subprocess.SubprocessError, ET.ParseError):
            time.sleep(1)
            continue
        labels = [n.get('text') or n.get('content-desc') or '' for n in nodes]
        history.append([label for label in labels if label])
        if any(label.lower() == 'use password' for label in labels):
            adb('emu', 'finger', 'touch', args.fingerprint)
            print('Sent emulator fingerprint to the native prompt')
            return
        time.sleep(1)
    raise RuntimeError('Biometric prompt did not appear: ' + repr(history[-5:]))


if __name__ == '__main__':
    main()
