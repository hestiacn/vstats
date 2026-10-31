"""Deterministic provider-collection/atomic-publication checks; no network."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'crawler-evidence.py'
SPEC = importlib.util.spec_from_file_location('collector_under_test', str(SOURCE))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Collection(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name) / 'evidence'
        self.raw = b'{"creationTime":"fixture","prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}\n'

    def record(self, second=0, raw=None):
        return C.record_snapshot(self.directory, self.raw if raw is None else raw,
                                 '2026-10-30T10:00:%02dZ' % second)

    def test_retrieval_time_does_not_follow_creation_time(self):
        result = self.record()
        data = json.loads((self.directory / 'evidence.json').read_text())
        attestation = json.loads(data['snapshots'][0]['attestation_json'])
        self.assertEqual(attestation['retrieved_at'], '2026-10-30T10:00:00Z')
        self.assertEqual(data['snapshots'][0]['raw_json'].encode(), self.raw)
        self.assertEqual(result['raw_sha256'], hashlib.sha256(self.raw).hexdigest())

    def test_repeat_idempotency_and_content_deduplication(self):
        self.record()
        self.record()
        self.record(1)
        self.assertEqual(len(list((self.directory / 'raw').iterdir())), 1)
        self.assertEqual(len(list((self.directory / 'retrievals').iterdir())), 2)
        self.assertEqual(len(json.loads((self.directory / 'evidence.json').read_text())['snapshots']), 2)

    def test_conflicting_time_preserves_bundle(self):
        self.record()
        before = (self.directory / 'evidence.json').read_bytes()
        with self.assertRaises(ValueError):
            self.record(raw=self.raw.replace(b'192.0.2.0/24', b'198.51.100.0/24'))
        self.assertEqual((self.directory / 'evidence.json').read_bytes(), before)

    def test_invalid_download_preserves_bundle(self):
        self.record()
        before = (self.directory / 'evidence.json').read_bytes()
        malformed = [b'{}', b'{"creationTime":"x","prefixes":[]}',
                     self.raw.replace(b'192.0.2.0/24', b'192.0.2.1/24'),
                     self.raw.replace(b'ipv4Prefix', b'ipv6Prefix'),
                     self.raw.replace(b'192.0.2.0/24', b'192.0.2.0/255.255.255.0'),
                     b'{"creationTime":"x","creationTime":"y","prefixes":[]}',
                     b'x' * (C.MAX_RAW_BYTES + 1)]
        for raw in malformed:
            with self.subTest(size=len(raw)):
                with self.assertRaises(ValueError):
                    self.record(1, raw)
                self.assertEqual((self.directory / 'evidence.json').read_bytes(), before)

    def test_archived_tampering_preserves_bundle(self):
        self.record()
        before = (self.directory / 'evidence.json').read_bytes()
        archived = next((self.directory / 'retrievals').iterdir())
        content = json.loads(archived.read_text())
        content['attestation']['source_url'] = 'https://example.test/untrusted.json'
        archived.write_bytes(C.encoded(content))
        with self.assertRaises(ValueError):
            self.record(1)
        self.assertEqual((self.directory / 'evidence.json').read_bytes(), before)

    def test_snapshot_and_prefix_caps_keep_newest_evidence(self):
        with mock.patch.object(C, 'MAX_SNAPSHOTS', 3):
            for second in range(5):
                self.record(second)
            data = json.loads((self.directory / 'evidence.json').read_text())
            self.assertEqual([json.loads(x['attestation_json'])['retrieved_at'] for x in data['snapshots']],
                             ['2026-10-30T10:00:02Z', '2026-10-30T10:00:03Z', '2026-10-30T10:00:04Z'])
        with mock.patch.object(C, 'MAX_PREFIXES', 2):
            self.record(5)
            data = json.loads((self.directory / 'evidence.json').read_text())
            self.assertEqual(len(data['snapshots']), 2)
            self.assertEqual(json.loads(data['snapshots'][-1]['attestation_json'])['retrieved_at'], '2026-10-30T10:00:05Z')
        self.assertEqual(len(list((self.directory / 'retrievals').iterdir())), 6)

    def test_symlink_and_writable_targets_refused(self):
        self.record()
        bundle = self.directory / 'evidence.json'
        bundle.unlink()
        outside = Path(self.scratch.name) / 'outside'
        outside.write_text('original')
        bundle.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.record(1)
        self.assertEqual(outside.read_text(), 'original')
        bundle.unlink()
        self.record(2)
        os.chmod(str(bundle), 0o666)
        with self.assertRaises(ValueError):
            self.record(3)

    def test_download_failure_publishes_nothing(self):
        with mock.patch.object(C, 'download', side_effect=OSError('offline')):
            with self.assertRaises(OSError):
                C.collect(self.directory)
        self.assertFalse(self.directory.exists())

    def test_registered_download_and_redirect_refusal(self):
        self.assertIsNone(C.NoRedirect().redirect_request(None, None, 302, 'redirect', {},
                                                         'https://example.test/other.json'))
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = C.SOURCE_URL
        response.read.return_value = self.raw
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch.object(C.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(C.download(), self.raw)
            response.read.assert_called_once_with(C.MAX_RAW_BYTES + 1)
            request = opener.open.call_args[0][0]
            self.assertEqual(request.full_url, C.SOURCE_URL)
            response.geturl.return_value = 'https://example.test/other.json'
            with self.assertRaises(ValueError):
                C.download()


if __name__ == '__main__':
    unittest.main()
