"""Regression coverage for the disposable-emulator DocumentsUI driver."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('android_select_saf_folder', ROOT / 'tools/android_select_saf_folder.py')
picker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(picker)


def screen(label, enabled='true'):
    # Accessibility text controls are often leaves. bool(Element) is false for
    # leaf nodes even though the control exists and can be tapped.
    return f'<hierarchy><node text="{label}" enabled="{enabled}" bounds="[0,0][100,100]" /></hierarchy>'


class AndroidSafPickerTests(unittest.TestCase):
    def test_navigates_leaf_controls_and_accepts_uppercase_confirmation(self):
        screens = [screen('Documents'), screen('LinSCP-Ungranted-Smoke'),
                   screen('USE THIS FOLDER'), screen('ALLOW')]
        selected = []
        with patch.object(picker, 'dump', side_effect=screens), \
             patch.object(picker.time, 'sleep'), \
             patch.object(picker, 'click', side_effect=lambda node: selected.append(node.get('text'))):
            picker.main()
        self.assertEqual(selected, ['Documents', 'LinSCP-Ungranted-Smoke', 'USE THIS FOLDER', 'ALLOW'])


if __name__ == '__main__':
    unittest.main()
