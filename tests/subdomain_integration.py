#!/usr/bin/env python3
"""Exercise the real subdomain pipeline with link-time DNS/HTTP fixtures only."""
import csv
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

    def run_fixture(self, scenario='success', words=('www', 'mail'), code=0, color=None):
        (self.root / 'wordlist.txt').write_text('\n'.join(words) + '\n')
        started = time.monotonic()
        arguments = [BINARY, scenario] + ([color] if color is not None else [])
        result = subprocess.run(arguments, cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=12)
        self.assertEqual(result.returncode, code, (scenario, result.stdout[-5000:], result.stderr))
        self.last_stdout = result.stdout
        report = json.loads((self.root / 'fixture-report.json').read_text())
        self.assertEqual(report['fixture']['active_http'], 0)
        self.assertEqual(report['fixture']['http_after_cancel'], 0)
        return report, time.monotonic() - started

    def module_json(self):
        report = self.module_report()
        return report['subdomains'] + report['subdomain_candidates']

    def module_report(self):
        return json.loads((self.root / 'example.test_subdomains.json').read_text())

    def module_csv(self):
        with (self.root / 'example.test_subdomains.csv').open(newline='') as stream:
            return [json.loads(row['details']) for row in csv.DictReader(stream)
                    if row['record_type'] in ('subdomain', 'subdomain_candidate')]

    def test_dns_observations_are_exported_without_http(self):
        report, _ = self.run_fixture()
        self.assertEqual(report['status'], 'complete')
        self.assertEqual({row['sub'] for row in report['subdomains']}, {'www.example.test', 'mail.example.test'})
        self.assertEqual(report['fixture']['http_calls'], 0)
        self.assertEqual({row['sub'] for row in self.module_json()}, {'www.example.test', 'mail.example.test'})

    def test_automatic_exports_match_final_report_and_separate_candidates(self):
        for scenario, code in (('success', 0), ('mixed-failure', 1), ('dns-failure', 1), ('wildcard', 0), ('cancel', 130)):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario, code=code)
                canonical = {key: value for key, value in report.items() if key != 'fixture'}
                automatic = self.module_report()
                self.assertEqual(automatic, canonical)
                self.assertEqual(automatic['schema_version'], '3.0')
                self.assertEqual(automatic['tool_version'], 'dark-nexus/2.1.0')
                self.assertNotIn('results', automatic)
                expected_counts = {'resolved': len(report['subdomains']),
                                   'candidates': len(report['subdomain_candidates']),
                                   'total': len(report['subdomains']) + len(report['subdomain_candidates'])}
                self.assertEqual(automatic['subdomain_counts'], expected_counts)
                self.assertEqual(self.module_csv(), report['subdomains'] + report['subdomain_candidates'])
                checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
                self.assertTrue(checkpoint.pop('checkpoint')['final'])
                self.assertEqual(checkpoint, canonical)

    def test_wordlist_streaming_reaches_candidates_beyond_first_dns_batch(self):
        words = [f'unknown{index}' for index in range(10005)] + ['tailmarker']
        report, _ = self.run_fixture('streaming-tail', words=words)
        self.assertEqual([row['sub'] for row in report['subdomains']], ['tailmarker.example.test'])
        queried = self.non_probe_names(report)
        self.assertEqual(len(queried), len(words))
        self.assertEqual(queried[-1], 'tailmarker.example.test')

    def test_independent_feature_switches_control_actual_pipeline_work(self):
        cases = (
            ('feature-none', 0, 0, 0, 0),
            ('feature-http', 2, 0, 0, 0),
            ('feature-cname', 0, 2, 0, 0),
            ('feature-tech', 2, 0, 2, 0),
            ('feature-js', 2, 0, 0, 2),
            ('feature-hints', 2, 2, 0, 2),
        )
        for scenario, http, cname, tech, pages in cases:
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario)
                fixture = report['fixture']
                self.assertEqual(len(report['subdomains']), 2)
                self.assertEqual(fixture['http_calls'], http)
                self.assertEqual(fixture['cname_calls'], cname)
                self.assertEqual(fixture['tech_calls'], tech)
                self.assertEqual(fixture['page_calls'], pages)
                if scenario == 'feature-http':
                    self.assertEqual(fixture['head_calls'], 2)
                    self.assertEqual(fixture['get_calls'], 0)
                if scenario == 'feature-tech':
                    self.assertEqual(fixture['get_calls'], 2)
                    self.assertEqual(fixture['waf_calls'], 2)

    def test_ipv6_only_names_survive_without_enrichment(self):
        report, _ = self.run_fixture('ipv6')
        self.assertEqual(len(report['subdomains']), 2)
        for row in report['subdomains']:
            self.assertEqual(row['ips'], [])
            self.assertEqual(row['ipv6'], ['2001:db8::20'])
        self.assertTrue(all(row['ipv6'] == ['2001:db8::20'] for row in self.module_json()))
        self.assertEqual(report['fixture']['http_calls'], 0)

    def test_console_accents_preserve_plain_output_and_machine_reports(self):
        for color in ('always', 'never', 'auto'):
            with self.subTest(color=color):
                report, _ = self.run_fixture('presentation', color=color)
                output = self.last_stdout
                for value in ('192.0.2.20', '192.0.2.21', '2001:db8::20', 'CNAME: edge.example.test'):
                    self.assertIn(value, output)
                if color == 'always':
                    self.assertIn('\x1b[32m192.0.2.20', output)
                    self.assertIn('\x1b[32mIPv6:  2001:db8::20', output)
                    self.assertIn('\x1b[32mCNAME: edge.example.test', output)
                else:
                    self.assertNotIn('\x1b', output)
                self.assertEqual(len(report['subdomains']), 2)
                self.assertTrue(all(row['cname'] == 'edge.example.test' for row in report['subdomains']))
                self.assertTrue(all(row['server'] == 'fixture' for row in report['subdomains']))
                self.assertTrue(all(row['stack'] == ['FixtureStack'] for row in report['subdomains']))
                for filename in ('fixture-report.json', 'example.test_subdomains.json',
                                 'example.test_subdomains.csv', 'example.test_subdomains_checkpoint.json'):
                    self.assertNotIn('\x1b', (self.root / filename).read_text())

    def test_deep_js_relative_script_reaches_dns_discovery_pipeline(self):
        report, _ = self.run_fixture('js-relative', words=('www',))
        self.assertEqual({row['sub'] for row in report['subdomains']},
                         {'www.example.test', 'discovered.api.example.test'})
        self.assertEqual(report['subdomain_candidates'], [])
        self.assertEqual(report['fixture']['http_calls'], 2)
        self.assertIn('discovered.api.example.test', report['fixture']['requested'])
        discovered = next(row for row in report['subdomains'] if row['sub'] == 'discovered.api.example.test')
        self.assertEqual(discovered['source'], 'js')
        self.assertEqual(discovered['discovery_sources'], ['js'])
        self.assertEqual(discovered['doh_fallback'], '')
        self.assertEqual(report['fixture']['page_calls'], 1, 'cached HTML should leave only one script fetch')
        self.assertIn('cached=1', self.last_stdout)

    def test_js_discovery_reuses_successful_http_scheme(self):
        report, _ = self.run_fixture('js-http', words=('www',))
        self.assertEqual({row['sub'] for row in report['subdomains']},
                         {'www.example.test', 'discovered.api.example.test'})
        self.assertEqual(report['fixture']['page_calls'], 1)
        self.assertEqual(report['subdomains'][1]['http_observations'][0]['requested_url'][:7], 'http://')

    def test_compact_console_keeps_additional_addresses_in_reports(self):
        report, _ = self.run_fixture('presentation-compact')
        self.assertIn('192.0.2.20 (+1)', self.last_stdout)
        self.assertNotIn('192.0.2.21', self.last_stdout)
        self.assertTrue(all(row['ips'] == ['192.0.2.20', '192.0.2.21'] for row in report['subdomains']))
        self.assertTrue(all(row['ips'] == ['192.0.2.20', '192.0.2.21'] for row in self.module_json()))

    def test_js_observation_adds_source_without_repeating_successful_dns(self):
        report, _ = self.run_fixture('js-overlap', words=('www',))
        observed = next(row for row in report['subdomains'] if row['sub'] == 'discovered.api.example.test')
        self.assertEqual(observed['discovery_sources'], ['js', 'passive'])
        self.assertEqual(observed['source'], 'both')
        self.assertEqual(observed['doh_fallback'], '')
        self.assertEqual(self.non_probe_names(report).count('discovered.api.example.test'), 1)

    def test_partial_http_keeps_status_and_diagnostics_in_every_report(self):
        for scenario in ('http-truncated', 'http-timeout', 'http-headers-incomplete'):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario)
                self.assertEqual(report['status'], 'complete')
                rows = report['subdomains']
                self.assertEqual(len(rows), 2)
                for row in rows:
                    self.assertEqual(row['http_code'], '200')
                    self.assertEqual(row['title'], '')
                    expected_server = '' if scenario == 'http-headers-incomplete' else 'fixture'
                    self.assertEqual(row['server'], expected_server)
                    observation = row['http_observations'][0]
                    self.assertEqual(observation['http_code'], 200)
                    self.assertFalse(observation['body_complete'])
                    self.assertEqual(observation['timed_out'], scenario == 'http-timeout')
                    self.assertEqual(observation['truncated'], scenario != 'http-timeout')
                by_name = {row['sub']: row['http_observations'] for row in rows}
                for row in self.module_json():
                    self.assertEqual(row['http_observations'], by_name[row['sub']])
                checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
                for row in checkpoint['subdomains']:
                    self.assertEqual(row['http_observations'], by_name[row['sub']])
                for row in self.module_csv():
                    self.assertEqual(row['http_observations'], by_name[row['sub']])
                self.assertIn('[HTTP transfer incomplete]', self.last_stdout)

    def test_complete_404_keeps_its_status_and_title(self):
        report, _ = self.run_fixture('http-404')
        for row in report['subdomains']:
            self.assertEqual(row['http_code'], '404')
            self.assertIn('café', row['title'])
            observation = row['http_observations'][0]
            self.assertTrue(observation['body_complete'])
            self.assertFalse(observation['success'])

    def test_partial_js_page_or_script_is_not_used_for_discovery(self):
        for scenario in ('js-partial-page', 'js-partial-script'):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario, words=('www',))
                self.assertEqual({row['sub'] for row in report['subdomains']}, {'www.example.test'})
                self.assertNotIn('discovered.api.example.test', report['fixture']['requested'])

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

    def test_temporary_failures_recover_at_lower_concurrency(self):
        report, _ = self.run_fixture('dns-transient')
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['subdomains']), 2)
        self.assertEqual(len(self.non_probe_names(report)), 4)
        initial, retry = report['fixture']['dns_concurrencies']
        self.assertEqual(initial, 128)
        self.assertLess(retry, initial)
        self.assertEqual(report['fixture']['dns_timeouts'], [500, 1000])
        self.assertIn('[dns recovered]', self.last_stdout)

    def test_retry_preserves_previously_successful_family(self):
        report, _ = self.run_fixture('dns-partial-transient')
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['subdomains']), 2)
        for row in report['subdomains']:
            self.assertEqual(row['ips'], ['192.0.2.20'])
            self.assertEqual(row['ipv6'], ['2001:db8::20'])

    def test_retry_budget_and_disabling_retries_are_respected(self):
        for scenario, queries in (('dns-exhausted', 4), ('dns-no-retry', 2), ('dns-failure', 2), ('dns-permanent', 2)):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario, code=1)
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(len(self.non_probe_names(report)), queries)
                self.assertEqual(len(report['errors']), 1)

    def test_two_retries_can_recover_without_adding_an_extra_attempt(self):
        report, _ = self.run_fixture('dns-two-retries')
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(self.non_probe_names(report)), 6)
        self.assertEqual(report['fixture']['dns_timeouts'], [500, 1000, 1500])

    def test_dns_progress_is_checkpointed_without_positive_discoveries(self):
        report, _ = self.run_fixture('checkpoint-progress', words=[f'host{i}' for i in range(1000)])
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['subdomains'], [])
        self.assertTrue(report['fixture']['observed_running_empty_checkpoint'])
        self.assertGreater(report['fixture']['observed_checkpoint_checks'], 0)
        self.assertLess(report['fixture']['observed_checkpoint_checks'], 1000)
        self.assertEqual(report['subdomain_dns']['candidate_checks'], 1000)

    def test_sustained_dns_outage_stops_discovery_and_exports_reason(self):
        words = [f'host{index}' for index in range(10005)]
        report, _ = self.run_fixture('dns-exhausted', words=words, code=1)
        stats = report['subdomain_dns']
        self.assertTrue(stats['stopped_early'])
        self.assertIn('remaining candidates were not checked', stats['stop_reason'])
        self.assertEqual(report['status'], 'failed')
        self.assertLess(stats['candidate_checks'], len(words))
        self.assertEqual(stats['incomplete_checks'], stats['candidate_checks'])
        self.assertEqual(len(self.non_probe_names(report)), stats['candidate_checks'] * 2)
        self.assertEqual(len(report['errors']), 2)
        self.assertTrue(any(stats['stop_reason'] == error for error in report['errors']))
        self.assertEqual(self.module_report()['subdomain_dns'], stats)
        self.assertEqual(stats['unattempted_queries'], 0)

    def test_recovery_and_negative_replies_do_not_trigger_outage_stop(self):
        words = [f'host{index}' for index in range(10005)]
        report, _ = self.run_fixture('dns-outage-recovery', words=words, code=1)
        stats = report['subdomain_dns']
        self.assertFalse(stats['stopped_early'])
        self.assertEqual(stats['candidate_checks'], len(words))
        self.assertEqual(stats['incomplete_checks'], 640)
        self.assertIn('host10004.example.test', self.non_probe_names(report))
        self.assertEqual(stats['concurrency_final'], stats['concurrency_initial'])

    def test_local_queue_deadline_does_not_reduce_resolver_concurrency(self):
        report, _ = self.run_fixture('dns-queue-recovery')
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['fixture']['dns_concurrencies'], [128, 128])
        stats = report['subdomain_dns']
        self.assertEqual(stats['temporary_failures'], 0)
        self.assertEqual(stats['deadline_queries'], 4)
        self.assertEqual(stats['unattempted_queries'], 4)
        self.assertEqual(stats['submitted_queries'], 4)
        self.assertEqual(stats['recovered_checks'], 2)

    def test_repeated_hostname_keeps_addresses_observed_in_later_batches(self):
        report, _ = self.run_fixture('duplicate-family')
        rows = [row for row in report['subdomains'] if row['sub'] == 'www.example.test']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ips'], ['192.0.2.20'])
        self.assertEqual(rows[0]['ipv6'], ['2001:db8::20'])
        module_rows = [row for row in self.module_json() if row['sub'] == 'www.example.test']
        self.assertEqual(module_rows[0]['ipv6'], ['2001:db8::20'])

    def test_doh_provider_names_describe_only_families_with_addresses(self):
        for scenario, expected in (('doh-provider-keep', 'cloudflare'),
                                   ('doh-provider-merge', 'cloudflare,google')):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario, words=('mail',), code=1)
                self.assertEqual(report['status'], 'partial')
                self.assertTrue(report['errors'])
                row = next(row for row in self.module_json() if row['sub'] == 'www.example.test')
                self.assertEqual(row['doh_fallback'], expected)
                self.assertEqual(row['ips'], ['192.0.2.42'])
                self.assertEqual(row['ipv6'], ['2001:db8::42'] if scenario == 'doh-provider-merge' else [])
                self.assertEqual(row['dns_status'], 'uncertain')
                self.assertFalse(row['wildcard_match'])
                self.assertEqual(self.candidate_names(report), {'www.example.test'})
                self.assertEqual({row['sub'] for row in report['subdomains']}, {'mail.example.test'})
                self.assertEqual(report['fixture']['http_calls'], 1)
                self.assertNotIn('www.example.test', report['fixture']['http_addresses'])
                self.assertTrue(any('DoH observations remain uncertain' in warning for warning in report['warnings']))

    def test_native_recovery_promotes_doh_candidates_without_mixing_addresses(self):
        report, _ = self.run_fixture('doh-native-recovery', words=('www', 'second', 'kept'), code=1)
        self.assertEqual(report['status'], 'partial')  # Earlier native failures remain in run diagnostics.
        self.assertEqual({row['sub'] for row in report['subdomains']}, {'www.example.test', 'second.example.test'})
        self.assertEqual(self.candidate_names(report), {'kept.example.test'})
        self.assertEqual(report['subdomain_counts'], {'resolved': 2, 'candidates': 1, 'total': 3})
        self.assertEqual(report['fixture']['http_calls'], 2)
        for row in report['subdomains']:
            self.assertEqual(row['ips'], ['192.0.2.20'])
            self.assertEqual(row['doh_fallback'], '')
            self.assertEqual(set(row['discovery_sources']), {'passive', 'brute'})
            self.assertEqual(report['fixture']['http_addresses'][row['sub']], ['192.0.2.20'])
        self.assertEqual(report['subdomain_candidates'][0]['ips'], ['192.0.2.42'])

    def test_http_enrichment_receives_both_dns_families_and_exports_selected_peer(self):
        for scenario, expected in (('presentation', ['192.0.2.20', '192.0.2.21', '2001:db8::20']),
                                   ('http-ipv6', ['2001:db8::20'])):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario, words=('www',))
                self.assertEqual(report['fixture']['http_addresses']['www.example.test'], expected)
                for rows in (report['subdomains'], self.module_json(), self.module_csv()):
                    observation = rows[0]['http_observations'][0]
                    self.assertTrue(observation['dns_pinned'])
                    self.assertEqual(observation['primary_ip'], expected[0])

    def test_cancellation_discards_queue_but_retains_discovered_dns(self):
        words = [f'host{index}' for index in range(2500)]
        report, elapsed = self.run_fixture('cancel', words=words, code=130)
        self.assertEqual(report['status'], 'cancelled')
        discovered = set(self.non_probe_names(report))
        self.assertGreater(len(discovered), 0)
        self.assertLess(len(discovered), len(words))
        self.assertEqual({row['sub'] for row in report['subdomains']}, discovered)
        self.assertGreater(report['fixture']['http_calls'], 0)
        self.assertLess(report['fixture']['http_calls'], 10)
        # Bound scan/worker shutdown; final report serialization is amplified by sanitizers.
        self.assertLess(report['duration_ms'], 4000)
        self.assertEqual(len(self.module_json()), len(discovered))
        checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
        self.assertEqual(checkpoint['subdomain_counts']['total'], len(discovered))

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

    def candidate_names(self, report):
        return {row['sub'] for row in report['subdomain_candidates']}

    def non_probe_names(self, report):
        return [name for name in report['fixture']['requested'] if not name.startswith('dnxwc-')]

    def test_wildcard_scope_skips_generated_dns_and_retains_passive_evidence_separately(self):
        for scenario in ('wildcard', 'rotating-wildcard'):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario)
                self.assertEqual(report['status'], 'complete')
                self.assertEqual(report['subdomains'], [])
                self.assertEqual(self.candidate_names(report), {'observed.example.test'})
                self.assertEqual(self.non_probe_names(report), ['observed.example.test'])
                self.assertEqual(report['fixture']['http_calls'], 0)
                candidate = report['subdomain_candidates'][0]
                self.assertTrue(candidate['wildcard_match'])
                self.assertEqual(candidate['dns_status'], 'wildcard')
                self.assertEqual(candidate['ips'], ['192.0.2.20'])
                module = self.module_json()
                self.assertEqual(len(module), 1)
                self.assertEqual(module[0]['dns_status'], 'wildcard')
                self.assertTrue(any('wildcard' in warning.lower() for warning in report['warnings']))
                checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
                self.assertEqual(checkpoint['subdomain_counts'], {'resolved': 0, 'candidates': 1, 'total': 1})
                csv_rows = self.module_csv()
                self.assertEqual(csv_rows[0]['dns_status'], 'wildcard')

    def test_child_wildcard_is_checked_even_when_root_probes_are_negative(self):
        report, _ = self.run_fixture('nested-wildcard', words=('www', 'host.api'))
        self.assertEqual({row['sub'] for row in report['subdomains']}, {'www.example.test'})
        self.assertEqual(self.candidate_names(report), {'observed.api.example.test'})
        self.assertNotIn('host.api.example.test', self.non_probe_names(report))
        self.assertTrue(any(name.startswith('dnxwc-') and name.endswith('.api.example.test')
                            for name in report['fixture']['requested']))
        self.assertEqual(report['fixture']['http_calls'], 1)

    def test_clear_child_scope_is_not_rejected_by_root_wildcard_or_shared_ip(self):
        report, _ = self.run_fixture('root-wildcard-child-clear', words=('www', 'host.api'))
        self.assertEqual({row['sub'] for row in report['subdomains']},
                         {'observed.api.example.test', 'host.api.example.test'})
        self.assertEqual(report['subdomain_candidates'], [])
        self.assertNotIn('www.example.test', self.non_probe_names(report))
        self.assertTrue(all(row['dns_status'] == 'resolved' and not row['wildcard_match']
                            for row in report['subdomains']))
        self.assertEqual(report['fixture']['http_calls'], 2)

    def test_incomplete_wildcard_probes_never_become_a_clear_scope(self):
        for scenario in ('probe-failure', 'probe-mixed', 'probe-missing'):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario)
                self.assertEqual(report['subdomains'], [])
                self.assertEqual(self.candidate_names(report), {'observed.example.test'})
                self.assertEqual(self.non_probe_names(report), ['observed.example.test'])
                row = report['subdomain_candidates'][0]
                self.assertEqual(row['dns_status'], 'uncertain')
                self.assertFalse(row['wildcard_match'])
                self.assertEqual(report['fixture']['http_calls'], 0)
                self.assertTrue(report['warnings'])

    def test_temporary_wildcard_failures_recover_without_erasing_successful_families(self):
        for scenario in ('probe-transient', 'probe-partial-transient', 'probe-two-retries'):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario)
                self.assertEqual({row['sub'] for row in report['subdomains']},
                                 {'www.example.test', 'mail.example.test', 'observed.example.test'})
                self.assertEqual(report['subdomain_candidates'], [])
                self.assertEqual(report['fixture']['probe_timeouts'],
                                 [500, 1000, 1500] if scenario == 'probe-two-retries' else [500, 1000])
                self.assertLess(report['fixture']['probe_concurrencies'][1], report['fixture']['probe_concurrencies'][0])
                self.assertIn('[wildcard retry ', self.last_stdout)

    def test_wildcard_retry_budget_and_positive_evidence_remain_conservative(self):
        for scenario, attempts, status in (('probe-no-retry', 1, 'uncertain'),
                                          ('probe-exhausted', 2, 'uncertain'),
                                          ('probe-partial-positive', 2, 'uncertain'),
                                          ('probe-retry-positive', 2, 'wildcard')):
            with self.subTest(scenario=scenario):
                report, _ = self.run_fixture(scenario)
                self.assertEqual(report['subdomains'], [])
                self.assertEqual(self.candidate_names(report), {'observed.example.test'})
                self.assertEqual(report['subdomain_candidates'][0]['dns_status'], status)
                self.assertEqual(len(report['fixture']['probe_timeouts']), attempts)
                self.assertEqual(report['fixture']['http_calls'], 0)

    def test_wildcard_batch_deadline_accounts_for_queued_queries_and_remains_bounded(self):
        report, _ = self.run_fixture('probe-deadline', words=('www',))
        fixture = report['fixture']
        self.assertGreater(len(fixture['probe_deadlines']), 2)
        self.assertTrue(all(slots == 16 for slots in fixture['probe_concurrencies']))
        self.assertTrue(all(timeout == 5000 for timeout in fixture['probe_timeouts']))
        self.assertTrue(all(10000 <= deadline <= 30000 for deadline in fixture['probe_deadlines']))
        probes = {host for host in fixture['requested'] if host.startswith('dnxwc-')}
        self.assertEqual(len(probes), 6 + 63 * 3)
        self.assertTrue(report['subdomain_candidates'])  # Untested scopes exceed the independent 64-scope ceiling.

    def test_scope_probe_budget_keeps_unprobed_passive_names_uncertain(self):
        report, _ = self.run_fixture('scope-budget', words=('www',))
        probes = [name for name in report['fixture']['requested'] if name.startswith('dnxwc-')]
        parents = {name.split('.', 1)[1] for name in probes}
        self.assertLessEqual(len(parents), 64)
        self.assertLessEqual(len(probes), 6 + 63 * 3)
        candidates = report['subdomain_candidates']
        self.assertGreaterEqual(len(candidates), 37)
        self.assertTrue(all(row['dns_status'] == 'uncertain' for row in candidates))
        self.assertEqual(len(report['subdomains']) + len(candidates), 101)
        self.assertLessEqual(report['fixture']['http_calls'], 64)

    def test_passive_names_are_resolved_before_explicit_wordlist(self):
        report, _ = self.run_fixture('passive-first')
        queried = self.non_probe_names(report)
        self.assertEqual(queried[0], 'observed.example.test')
        self.assertEqual(set(queried), {'observed.example.test', 'www.example.test', 'mail.example.test'})

    def test_passive_only_disables_explicit_wordlist_and_permutations(self):
        report, _ = self.run_fixture('passive-only')
        self.assertEqual(self.non_probe_names(report), ['observed.example.test'])
        self.assertEqual([row['sub'] for row in report['subdomains']], ['observed.example.test'])

    def test_permutation_queries_are_bounded_after_passive_results(self):
        report, _ = self.run_fixture('permutation-budget', words=('www',))
        queried = self.non_probe_names(report)
        self.assertEqual(set(queried[:100]), {f'seed{1000 + index}unit.example.test' for index in range(100)})
        self.assertLessEqual(len(queried), 100 + 1 + 5000)
        self.assertGreater(len(queried), 101)
        mutated_seeds = {f'seed{1000 + index}unit' for index in range(100)
                         if any(f'seed{1000 + index}unit' in name.split('.', 1)[0]
                                for name in queried[101:])}
        self.assertLessEqual(len(mutated_seeds), 64)
        generated = [row for row in report['subdomains'] if 'permutation' in row['discovery_sources']]
        self.assertTrue(generated)

    def test_unicode_and_csv_quotes_survive_module_exports(self):
        report, _ = self.run_fixture('unicode')
        expected = 'café Москва, "quoted"'
        self.assertTrue(all(row['title'] == expected for row in report['subdomains']))
        self.assertTrue(all(row['title'] == expected for row in self.module_json()))
        rows = self.module_csv()
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

    def test_csv_export_failure_is_reflected_in_json_and_checkpoint(self):
        destination = self.root / 'example.test_subdomains.csv'
        destination.mkdir()
        report, _ = self.run_fixture(code=1)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(self.module_report()['errors'], report['errors'])
        checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
        self.assertEqual(checkpoint['status'], 'partial')
        self.assertEqual(checkpoint['errors'], report['errors'])
        self.assertTrue(destination.is_dir())

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
