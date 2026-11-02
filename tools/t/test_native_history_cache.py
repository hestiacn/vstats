import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('native_history_cache', str(Path(__file__).resolve().parents[1] / 'native_history_cache.py'))
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'POSIX no-follow history snapshots')
class HistoryCache(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'awstats092026.example.test.txt'
        self.uid, self.gid = os.getuid(), os.getgid()

    def test_compressed_history_is_present_and_retains_its_representation(self):
        raw = gzip.compress(b'BEGIN_TIME 1\n0 1 1 100 0 0 0\nEND_TIME\n')
        Path(str(self.base) + '.gz').write_bytes(raw)
        snapshot = cache.read_history(self.base, self.uid)
        self.assertFalse(cache.matches_history(snapshot, None))
        self.assertTrue(cache.matches_history(snapshot, hashlib.sha256(raw).hexdigest()))
        self.assertEqual(snapshot['suffix'], '.gz')
        destination = cache.restore_history(snapshot, self.root / 'copy.txt', self.uid, self.gid)
        self.assertEqual(destination, str(self.root / 'copy.txt.gz'))
        self.assertEqual(Path(destination).read_bytes(), raw)
        self.assertEqual(gzip.decompress(Path(destination).read_bytes()), gzip.decompress(raw))
        self.assertFalse((self.root / 'copy.txt').exists())
        self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)

    def test_missing_plain_and_stale_snapshots(self):
        self.assertIsNone(cache.read_history(self.base, self.uid))
        self.assertTrue(cache.matches_history(None, None))
        self.assertFalse(cache.matches_history(None, 'a' * 64))
        self.assertIsNone(cache.restore_history(None, self.root / 'absent', self.uid, self.gid))
        self.base.write_bytes(b'plain history')
        Path(str(self.base) + '.gz').write_bytes(gzip.compress(b'stale gzip'))
        snapshot = cache.read_history(self.base, self.uid)
        self.assertEqual(snapshot['raw'], b'plain history')
        self.assertEqual(snapshot['suffix'], '')
        self.assertFalse(cache.matches_history(snapshot, 'b' * 64))
        snapshot['raw'] = b'changed'
        with self.assertRaises(ValueError):
            cache.restore_history(snapshot, self.root / 'changed', self.uid, self.gid)
        self.assertFalse((self.root / 'changed').exists())

    def test_owner_type_symlink_cap_and_existing_target_guards(self):
        self.base.write_bytes(b'history')
        with self.assertRaises(ValueError):
            cache.read_history(self.base, self.uid + 1)
        with self.assertRaises(ValueError):
            cache.read_history(self.base, self.uid, max_bytes=1)
        with self.assertRaises(ValueError):
            cache.read_history(self.base, self.uid, max_bytes=True)
        snapshot = cache.read_history(self.base, self.uid)
        destination = self.root / 'existing'
        destination.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            cache.restore_history(snapshot, destination, self.uid, self.gid)
        self.assertEqual(destination.read_bytes(), b'keep')
        self.base.unlink()
        self.base.symlink_to(destination)
        with self.assertRaises(OSError):
            cache.read_history(self.base, self.uid)
        self.base.unlink()
        self.base.mkdir()
        with self.assertRaises((OSError, ValueError)):
            cache.read_history(self.base, self.uid)
