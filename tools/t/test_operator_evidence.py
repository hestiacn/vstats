import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('operator_evidence_test', str(ROOT / 'tools/operator-evidence.py'))
evidence = importlib.util.module_from_spec(spec); spec.loader.exec_module(evidence)


class OperatorEvidence(unittest.TestCase):
    def config(self):
        return {'schema_version': 1, 'authorized': True, 'selection': 'Synthetic explicit candidates only',
                'addresses': ['192.0.2.1'], 'resolver': {'address': '192.0.2.53', 'nonrewriting': True},
                'source_document_fetched_at': 50}

    def test_collector_never_discovers_other_sources(self):
        asked = []
        def ask(resolver, owner, kind):
            asked.append((resolver, owner, kind))
            row = {'owner': owner, 'ttl': 30, 'type': kind,
                   'data': 'unit.internet-census.org' if kind == 'PTR' else '192.0.2.1'}
            return {'qname': owner, 'qtype': kind, 'status': 'NOERROR', 'truncated': 0, 'answers': [row]}
        result = evidence.collect(self.config(), ask=ask, now=lambda: 100)
        self.assertEqual([r[2] for r in asked], ['PTR', 'A'])
        self.assertEqual(result['observations'][0]['completed_at'], 100)
        self.assertEqual(result['observations'][0]['client'], '192.0.2.1')
        self.assertNotIn('verified', result['observations'][0])

    def test_unrelated_ptr_does_not_trigger_forward_queries(self):
        def ask(resolver, owner, kind):
            self.assertEqual(kind, 'PTR')
            return {'qname': owner, 'qtype': kind, 'status': 'NOERROR', 'truncated': 0,
                    'answers': [{'owner': owner, 'ttl': 30, 'type': kind, 'data': 'unit.internet-census.org.attacker.test'}]}
        self.assertEqual(len(evidence.collect(self.config(), ask=ask, now=lambda: 100)['observations'][0]['queries']), 1)

    def test_scope_requires_explicit_authorization(self):
        for key, value in [('authorized', False), ('addresses', []), ('addresses', ['192.0.2.1'] * 2),
                           ('addresses', ['192.000.002.001']), ('addresses', ['fe80::1%eth0'])]:
            config = self.config(); config[key] = value
            with self.assertRaises(ValueError):
                evidence.collect(config, ask=lambda *args: self.fail('Invalid scope queried DNS'))

    def test_mapped_ipv6_normalization(self):
        self.assertEqual(str(evidence.address('::ffff:192.0.2.1')), '192.0.2.1')

    def test_wire_parser_keeps_only_answer_section(self):
        wire = (b';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
                b';; flags: qr rd ra; QUERY: 1, ANSWER: 1\n\n'
                b';; ANSWER SECTION:\nunit.internet-census.org. 12 IN A 192.0.2.1\n\n'
                b';; ADDITIONAL SECTION:\noffchain.test. 60 IN A 192.0.2.2\n')
        result = evidence.parse_answer(wire, 'unit.internet-census.org', 'A')
        self.assertEqual(result['truncated'], 0)
        self.assertEqual(result['answers'], [{'owner': 'unit.internet-census.org', 'ttl': 12, 'type': 'A', 'data': '192.0.2.1'}])

    def test_truncation_is_explicit(self):
        result = evidence.parse_answer(b';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr tc rd ra; QUERY: 1;\n', 'example.test', 'A')
        self.assertEqual(result['truncated'], 1)


if __name__ == '__main__':
    unittest.main()
