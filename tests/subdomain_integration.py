#!/usr/bin/env python3
"""Exercise the real subdomain pipeline with link-time DNS/HTTP fixtures only."""
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve())


class SubdomainPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dark-nexus-subdomain-')
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, HOME=str(self.root), PATH=str(self.root),
                                NO_COLOR='1', TERM='dumb')
        for name in ('VT_API_KEY', 'ST_API_KEY', 'SHODAN_API_KEY', 'CENSYS_API_ID',
                     'CENSYS_API_SECRET'):
            self.environment.pop(name, None)

    def tearDown(self):
        self.temporary.cleanup()

    def run_fixture(self, scenario='success', words=('www', 'mail'), code=0):
        (self.root / 'wordlist.txt').write_text('\n'.join(words) + '\n')
        started = time.monotonic()
        result = subprocess.run([BINARY, scenario], cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=12)
        self.assertEqual(result.returncode, code, (scenario, result.stdout[-5000:], result.stderr))
        report = json.loads((self.root / 'fixture-report.json').read_text())
        self.assertEqual(report['fixture']['active_http'], 0)
        self.assertEqual(report['fixture']['http_after_cancel'], 0)
        return report, time.monotonic() - started

    def module_json(self):
        return json.loads((self.root / 'example.test_subdomains.json').read_text())

    def test_dns_observations_are_exported_without_http(self):
        report, _ = self.run_fixture()
        self.assertEqual(report['status'], 'complete')
        self.assertEqual({row['sub'] for row in report['subdomains']}, {'www.example.test', 'mail.example.test'})
        self.assertEqual(report['fixture']['http_calls'], 0)
        self.assertEqual({row['subdomain'] for row in self.module_json()}, {'www.example.test', 'mail.example.test'})

    def test_ipv6_only_names_survive_without_enrichment(self):
        report, _ = self.run_fixture('ipv6')
        self.assertEqual(len(report['subdomains']), 2)
        for row in report['subdomains']:
            self.assertEqual(row['ips'], [])
            self.assertEqual(row['ipv6'], ['2001:db8::20'])
        self.assertTrue(all(row['ipv6'] == ['2001:db8::20'] for row in self.module_json()))
        self.assertEqual(report['fixture']['http_calls'], 0)

    def test_dns_operational_failure_differs_from_negative_answer(self):
        negative, _ = self.run_fixture('nxdomain')
        self.assertEqual(negative['status'], 'complete')
        self.assertEqual(negative['errors'], [])
        self.assertEqual(negative['subdomains'], [])
        failed, _ = self.run_fixture('dns-failure', code=1)
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(failed['subdomains'], [])
        self.assertTrue(any('fixture resolver timeout' in error for error in failed['errors']))

    def test_one_family_failure_keeps_other_family_observations(self):
        report, _ = self.run_fixture('mixed-failure', code=1)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(report['subdomains']), 2)
        self.assertTrue(all(row['ips'] == ['192.0.2.20'] for row in report['subdomains']))
        self.assertTrue(report['errors'])

    def test_repeated_hostname_keeps_addresses_observed_in_later_batches(self):
        report, _ = self.run_fixture('duplicate-family')
        rows = [row for row in report['subdomains'] if row['sub'] == 'www.example.test']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ips'], ['192.0.2.20'])
        self.assertEqual(rows[0]['ipv6'], ['2001:db8::20'])
        module_rows = [row for row in self.module_json() if row['subdomain'] == 'www.example.test']
        self.assertEqual(module_rows[0]['ipv6'], ['2001:db8::20'])

    def test_doh_provider_names_describe_only_families_with_addresses(self):
        for scenario, expected in (('doh-provider-keep', 'cloudflare'),
                                   ('doh-provider-merge', 'cloudflare,google')):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario, words=('mail',), code=1)
                self.assertEqual(report['status'], 'partial')
                self.assertTrue(report['errors'])
                row = next(row for row in self.module_json() if row['subdomain'] == 'www.example.test')
                self.assertEqual(row['doh_fallback'], expected)
                self.assertEqual(row['ipv4'], ['192.0.2.42'])
                self.assertEqual(row['ipv6'], ['2001:db8::42'] if scenario == 'doh-provider-merge' else [])

    def test_cancellation_discards_queue_but_retains_discovered_dns(self):
        words = [f'host{index}' for index in range(2500)]
        report, elapsed = self.run_fixture('cancel', words=words, code=130)
        self.assertEqual(report['status'], 'cancelled')
        self.assertEqual(len(report['subdomains']), len(words))
        self.assertGreater(report['fixture']['http_calls'], 0)
        self.assertLess(report['fixture']['http_calls'], 10)
        self.assertLess(elapsed, 4)
        self.assertEqual(len(self.module_json()), len(words))
        checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
        self.assertEqual(checkpoint['count'], len(words))

    def test_worker_exception_preserves_dns_instead_of_terminating(self):
        report, _ = self.run_fixture('worker-throw', code=1)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(report['subdomains']), 2)
        self.assertTrue(any('fixture HTTP worker failure' in error for error in report['errors']))
        self.assertEqual(len(self.module_json()), 2)

    def test_passive_candidates_are_normalized_and_scoped_before_dns(self):
        report, _ = self.run_fixture('passive-invalid')
        self.assertEqual({row['sub'] for row in report['subdomains']},
                         {'www.example.test', 'mail.example.test', 'valid.example.test'})
        observed = [name for name in report['fixture']['requested'] if not name.startswith('dnxwc-')]
        self.assertEqual(set(observed), {'www.example.test', 'mail.example.test', 'valid.example.test'})

    def test_invalid_explicit_wordlist_does_not_start_builtin_candidates(self):
        for words in ((), ('# comment', 'bad name', '+option', '*')):
            with self.subTest(words=words):
                report, _ = self.run_fixture('success', words=words, code=1)
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(report['subdomains'], [])
                self.assertTrue(report['errors'])
                self.assertFalse(any(not name.startswith('dnxwc-') for name in report['fixture']['requested']))

    def test_wildcard_matches_are_retained_as_uncertain(self):
        report, _ = self.run_fixture('wildcard')
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(len(report['subdomains']), 2)
        self.assertTrue(all(row['wildcard_match'] for row in report['subdomains']))
        self.assertTrue(all(row['wildcard_match'] for row in self.module_json()))
        self.assertTrue(any('wildcard' in warning.lower() for warning in report['warnings']))

    def test_unicode_and_csv_quotes_survive_module_exports(self):
        report, _ = self.run_fixture('unicode')
        expected = 'café Москва, "quoted"'
        self.assertTrue(all(row['title'] == expected for row in report['subdomains']))
        self.assertTrue(all(row['title'] == expected for row in self.module_json()))
        rows = list(csv.DictReader(io.StringIO((self.root / 'example.test_subdomains.csv').read_text())))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['title'] == expected for row in rows))

    def test_predictable_tmp_symlinks_cannot_modify_their_targets(self):
        victim = self.root / 'keep.txt'
        victim.write_text('keep this content')
        for filename in ('example.test_subdomains.json', 'example.test_subdomains.csv',
                         'example.test_subdomains_checkpoint.json'):
            (self.root / (filename + '.tmp')).symlink_to(victim)
        report, _ = self.run_fixture()
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(victim.read_text(), 'keep this content')
        self.assertEqual(len(self.module_json()), 2)
        self.assertFalse(list(self.root.glob('*.tmp.*')))

    def test_destination_symlink_is_replaced_without_truncating_its_target(self):
        victim = self.root / 'keep.txt'
        victim.write_text('old destination target')
        destination = self.root / 'example.test_subdomains.json'
        destination.symlink_to(victim)
        self.run_fixture()
        self.assertEqual(victim.read_text(), 'old destination target')
        self.assertFalse(destination.is_symlink())
        self.assertEqual(len(self.module_json()), 2)

    def test_final_export_failure_is_reported_and_dns_is_retained(self):
        destination = self.root / 'example.test_subdomains.json'
        destination.mkdir()
        (destination / 'previous').write_text('keep')
        report, _ = self.run_fixture(code=1)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(report['subdomains']), 2)
        self.assertTrue(report['errors'])
        self.assertEqual((destination / 'previous').read_text(), 'keep')
        self.assertFalse(list(self.root.glob('*.tmp.*')))

    def test_atomic_write_failure_preserves_existing_file_and_cleans_temporary(self):
        target = self.root / 'atomic.json'
        target.write_text('previous file')
        report, _ = self.run_fixture('atomic-failure')
        self.assertEqual(report['errors'], [])
        self.assertEqual(target.read_text(), 'previous file')
        self.assertFalse(list(self.root.glob('atomic.json.tmp.*')))

    def test_concurrent_atomic_writers_leave_one_complete_file(self):
        report, _ = self.run_fixture('atomic-concurrent')
        self.assertEqual(report['errors'], [])
        result = json.loads((self.root / 'atomic.json').read_text())
        self.assertIn(result['writer'], range(8))
        self.assertEqual(result['payload'], 'x' * 4096)
        self.assertFalse(list(self.root.glob('atomic.json.tmp.*')))


if __name__ == '__main__':
    unittest.main()
