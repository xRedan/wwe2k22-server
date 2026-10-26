"""Package integrity regressions; uses only temporary, owned bundle files."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_build', ROOT / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

class PackageTests(unittest.TestCase):

    def setUp(self):
        (ROOT / 'dist').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-native-package-', dir=ROOT / 'dist')
        self.root = Path(self.temporary.name).resolve()
        assert self.root.is_relative_to((ROOT / 'dist').resolve())
        self.addCleanup(self.temporary.cleanup)
        self.output = self.root / 'bundle'
        self.output.mkdir()
        self.archive = self.root / 'client.zip'
        self.manifest = {'kind': 'native-client', 'target_sha256': build.TARGET, 'runtime_files': list(build.RUNTIME_FILES), 'package_files': list(build.PACKAGE_FILES), 'files': {}}
        for name in build.RUNTIME_FILES + build.LICENSE_FILES:
            data = ('fixture: ' + name).encode()
            (self.output / name).write_bytes(data)
            self.manifest['files'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        self.save_manifest()

    def save_manifest(self):
        (self.output / 'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')

    def test_exact_archive_and_ignored_extra_files(self):
        (self.output / 'unwanted.js').write_text('do not distribute')
        build.package(self.output, self.archive)
        with zipfile.ZipFile(self.archive) as archive:
            self.assertEqual(sorted(archive.namelist()), sorted(('wwe2k22-client/' + n for n in build.PACKAGE_FILES)))
            self.assertIsNone(archive.testzip())

    def test_modified_runtime_rejected_without_replacing_previous_archive(self):
        self.archive.write_bytes(b'previous')
        (self.output / 'dinput8.dll').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            build.package(self.output, self.archive)
        self.assertEqual(self.archive.read_bytes(), b'previous')

    def test_incomplete_manifest_rejected(self):
        self.manifest['files'].pop('dinput8.dll')
        self.save_manifest()
        with self.assertRaises(ValueError):
            build.package(self.output, self.archive)

    def test_owned_fixture_cannot_be_published_as_game_build(self):
        self.manifest['kind'] = 'owned-test-native-client'
        self.save_manifest()
        with self.assertRaises(ValueError):
            build.package(self.output, self.archive)

    def test_failed_zip_write_is_atomic_and_cleans_temporary_file(self):
        self.archive.write_bytes(b'previous')
        with patch.object(zipfile.ZipFile, 'writestr', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                build.package(self.output, self.archive)
        self.assertEqual(self.archive.read_bytes(), b'previous')
        self.assertEqual(list(self.root.glob('*.tmp')), [])

    def test_archive_cannot_overwrite_its_own_input(self):
        original = (self.output / 'dinput8.dll').read_bytes()
        with self.assertRaises(ValueError):
            build.package(self.output, self.output / 'dinput8.dll')
        self.assertEqual((self.output / 'dinput8.dll').read_bytes(), original)

    def test_atomic_file_write_preserves_old_file_if_replace_fails(self):
        target = self.output / 'example'
        target.write_bytes(b'old')
        with patch.object(build.os, 'replace', side_effect=OSError('locked')):
            with self.assertRaises(OSError):
                build.atomic_write(target, b'new')
        self.assertEqual(target.read_bytes(), b'old')
        self.assertEqual(list(self.output.glob('*.tmp')), [])
    def test_sanitized_client_cannot_be_built_as_production(self):
        with self.assertRaisesRegex(ValueError, 'owned-test'):
            build.build(self.output, self.root / 'compiler.exe', sanitizer='address')

if __name__ == '__main__':
    unittest.main()
