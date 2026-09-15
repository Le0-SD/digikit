"""tools/ghidraapply.py name splitting (the Ghidra parts need a project)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import ghidraapply  # noqa: E402


class SplitNameTest(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(ghidraapply.split_name('VoiceConfig::updateMirror'),
                         ['VoiceConfig', 'updateMirror'])

    def test_template_argument_keeps_its_colons(self):
        self.assertEqual(ghidraapply.split_name('Value<Digisharc::sound_struct>::updateMirror'),
                         ['Value<Digisharc::sound_struct>', 'updateMirror'])

    def test_spaces_become_underscores(self):
        self.assertEqual(ghidraapply.split_name('Value<unsigned int>'), ['Value<unsigned_int>'])


if __name__ == '__main__':
    unittest.main()
