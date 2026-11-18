"""Import-only isolation checks; no fixture, child, network, Git or DB access."""
import importlib.util
import os
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest.mock import patch

TEST_FILE = Path(__file__).resolve().with_name('test_oracle.py')
PRIVATE_NAME = '_forgeflow_dirty_target_oracle_research'

class ImportIsolationTests(unittest.TestCase):
    def load(self):
        return runpy.run_path(str(TEST_FILE), run_name='_forgeflow_oracle_import_probe')

    def test_existing_module_names_and_search_path_are_preserved(self):
        generic = types.ModuleType('oracle')
        private = types.ModuleType(PRIVATE_NAME)
        before = list(sys.path)
        with patch.dict(sys.modules, {'oracle': generic, PRIVATE_NAME: private}), \
             patch.dict(os.environ, {'ECP_ORACLE_FIXTURES': '/unused-private-fixtures'}), \
             patch.object(os, 'mkdir', side_effect=AssertionError('no fixture creation')):
            result = self.load()
            self.assertIs(sys.modules['oracle'], generic)
            self.assertIs(sys.modules[PRIVATE_NAME], private)
            self.assertEqual(sys.path, before)
            self.assertIsNot(result['oracle'], generic)
            self.assertIsNot(result['oracle'], private)
            self.assertEqual(Path(result['oracle'].__file__).resolve(), TEST_FILE.with_name('oracle.py'))

    def test_missing_fixture_root_fails_without_fallback(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(os, 'mkdir', side_effect=AssertionError('no fixture creation')):
            with self.assertRaisesRegex(RuntimeError, 'absolute private directory required'):
                self.load()

    def test_relative_fixture_root_fails_without_fallback(self):
        with patch.dict(os.environ, {'ECP_ORACLE_FIXTURES': 'relative-path'}), \
             patch.object(os, 'mkdir', side_effect=AssertionError('no fixture creation')):
            with self.assertRaisesRegex(RuntimeError, 'absolute private directory required'):
                self.load()

    def test_loader_failure_does_not_mutate_module_registry_or_path(self):
        class BrokenLoader:
            def create_module(self, spec):
                return None
            def exec_module(self, module):
                raise RuntimeError('synthetic loader failure')
        generic = types.ModuleType('oracle')
        private = types.ModuleType(PRIVATE_NAME)
        spec = importlib.util.spec_from_loader(PRIVATE_NAME, BrokenLoader())
        before = list(sys.path)
        with patch.dict(sys.modules, {'oracle': generic, PRIVATE_NAME: private}), \
             patch.dict(os.environ, {'ECP_ORACLE_FIXTURES': '/unused-private-fixtures'}), \
             patch.object(importlib.util, 'spec_from_file_location', return_value=spec):
            with self.assertRaisesRegex(RuntimeError, 'synthetic loader failure'):
                self.load()
            self.assertIs(sys.modules['oracle'], generic)
            self.assertIs(sys.modules[PRIVATE_NAME], private)
            self.assertEqual(sys.path, before)

if __name__ == '__main__':
    unittest.main(verbosity=2)
