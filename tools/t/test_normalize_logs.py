import hashlib
import importlib.util
import json
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

    def test_conflicting_identical_records_abstain(self):
        value = {'format': 'combined', 'vhost': 'example.test', 'scheme': 'https', 'client_source': 'socket_peer', 'user_agent': 'absent', 'referrer': 'absent'}
        other = dict(value, format='common', user_agent='unobserved', scheme='http')
        merged = normalizer.merge_observability(value, other)
        self.assertEqual(merged['user_agent'], 'unobserved')
        self.assertEqual(merged['scheme'], 'unknown')


if __name__ == '__main__':
    unittest.main()
