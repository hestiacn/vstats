import hashlib
import importlib.util
import json
import re
import textwrap
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('normalize_test', str(ROOT / 'tools/normalize_logs.py'))
normalizer = importlib.util.module_from_spec(spec); spec.loader.exec_module(normalizer)


class Observability(unittest.TestCase):
    def snapshot(self, rows, declared='combined'):
        temporary = tempfile.TemporaryDirectory(prefix='vstats-residual-normalize-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); logs = root / 'logs'; logs.mkdir()
        (logs / 'example-access_log').write_bytes(rows)
        path, receipt = normalizer.build_snapshot(str(logs), ['example-access_log'], str(root / 'work'),
            {'example-access_log': {'format': declared, 'vhost': 'example.test', 'scheme': 'https', 'client_source': 'socket_peer'}})
        metadata = json.loads((root / 'work/access.observability.json').read_bytes().decode('utf-8'))
        return Path(path).read_bytes(), receipt, metadata['records']

    def common(self, path='/'):
        return ('192.0.2.1 - - [01/Nov/2026:12:00:00 +0000] "GET ' + path + ' HTTP/1.1" 200 20').encode()

    def test_documented_log_sources_example_produces_trusted_observability(self):
        docs = (ROOT / 'docs/filters.md').read_text(encoding='utf-8')
        fence = chr(96) * 3
        blocks = [b for b in re.findall(fence + r'json[ \t]*\n(.*?)\n[ \t]*' + fence, docs, re.S) if '"log_sources"' in b]
        self.assertEqual(len(blocks), 1)
        settings = json.loads(textwrap.dedent(blocks[0]))
        with tempfile.TemporaryDirectory(prefix='vstats-doc-provenance-') as temporary:
            root = Path(temporary); logs = root / 'logs'; logs.mkdir()
            (logs / 'example-access_log').write_bytes(self.common() + b' "-" "SyntheticCrawler/1.0"\n')
            path, _ = normalizer.build_snapshot(str(logs), ['example-access_log'], str(root / 'work'), settings['log_sources'])
            metadata = json.loads((root / 'work/access.observability.json').read_text(encoding='utf-8'))['records']
            item = metadata[hashlib.sha256(Path(path).read_bytes().rstrip(b'\n')).hexdigest()]
            self.assertEqual(item['vhost'], 'example.test')
            self.assertEqual(item['client_source'], 'socket_peer')
            self.assertEqual(item['user_agent'], 'value')

    def test_common_is_unobserved(self):
        raw, receipt, metadata = self.snapshot(self.common() + b'\n', 'common')
        item = metadata[hashlib.sha256(raw.rstrip(b'\n')).hexdigest()]
        self.assertEqual(item['user_agent'], 'unobserved')
        self.assertEqual(item['referrer'], 'unobserved')
        self.assertEqual(item['client_source'], 'socket_peer')
        self.assertTrue(raw.endswith(b' "-" "-"\n'))

    def test_observed_absence_differs_from_unobserved(self):
        raw, receipt, metadata = self.snapshot(self.common() + b' "-" "-"\n')
        self.assertEqual(next(iter(metadata.values()))['user_agent'], 'absent')

    def test_observed_value(self):
        raw, receipt, metadata = self.snapshot(self.common() + b' "-" "SyntheticClient/1"\n')
        item = next(iter(metadata.values()))
        self.assertEqual(item['user_agent'], 'value')
        self.assertEqual(item['vhost'], 'example.test')

    def test_mixed_file_does_not_guess_format_per_line(self):
        rows = self.common() + b'\n' + self.common('/a') + b' "-" "SyntheticClient/1"\n'
        raw, receipt, metadata = self.snapshot(rows)
        self.assertEqual(receipt['files'][0]['source_format'], 'ambiguous')
        self.assertEqual({v['user_agent'] for v in metadata.values()}, {'unobserved'})

    def test_tagged_connection_fields_preserve_native_bytes(self):
        classic = b'192.0.2.1 - - [08/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 123 "https://example.test/" "Synthetic/1"'
        extra = b' VSTATS2 54321 2 "same-origin" "navigate" "document" "\\x22Windows\\x22"'
        expected = normalizer.normalize(classic + b'\n')[1]
        stamp, normalized, kind, fields = normalizer.normalize(classic + extra + b'\n', with_fields=True)
        self.assertEqual(normalized, expected)
        self.assertEqual(kind, 'combined')
        self.assertEqual(fields, {'remote_port': 54321, 'keepalive': 2, 'fetch_site': 'same-origin',
                                 'fetch_mode': 'navigate', 'fetch_dest': 'document', 'platform': 'Windows'})
        raw, receipt, metadata = self.snapshot(classic + extra + b'\n')
        self.assertEqual(raw, expected)
        self.assertEqual(next(iter(metadata.values()))['connection_fields'], fields)

    def test_connection_conflicts_and_invalid_ports_abstain(self):
        classic = b'192.0.2.1 - - [08/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Synthetic/1"'
        with self.assertRaises(ValueError):
            normalizer.normalize(classic + b' VSTATS2 99999 0 "-" "-" "-" "-"\n')
        value = {'format': 'combined', 'vhost': 'example.test', 'scheme': 'https', 'client_source': 'socket_peer',
                 'user_agent': 'value', 'referrer': 'absent', 'connection_fields': {'remote_port': 1234, 'keepalive': 0}}
        other = dict(value, connection_fields={'remote_port': 4321, 'keepalive': 0})
        self.assertIsNone(normalizer.merge_observability(value, other)['connection_fields'])

    def test_conflicting_identical_records_abstain(self):
        value = {'format': 'combined', 'vhost': 'example.test', 'scheme': 'https', 'client_source': 'socket_peer', 'user_agent': 'absent', 'referrer': 'absent'}
        other = dict(value, format='common', user_agent='unobserved', scheme='http')
        merged = normalizer.merge_observability(value, other)
        self.assertEqual(merged['user_agent'], 'unobserved')
        self.assertEqual(merged['scheme'], 'unknown')


if __name__ == '__main__':
    unittest.main()
