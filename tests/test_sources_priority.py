from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import main
from vmess_priority import load_recent_results, prioritize_configs, source_label
from vmess_sources import collect_links
from vmess_telegram import collect_telegram_links, telegram_preview_url
from vmess_types import AppError, LinkResult, parse_link


NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


def uri(number, remark=""):
    return "vless://00000000-0000-0000-0000-%012d@server%d.example:443?security=tls&sni=test.example&type=ws&path=%%2F#%s" % (
        number, number, remark)


def post(number, text, date=None):
    stamp = (date or NOW).isoformat()
    return ('<div class="tgme_widget_message" data-post="channel/%d">'
            '<div class="tgme_widget_message_text js-message_text">%s</div>'
            '<div><time datetime="%s"></time></div></div>') % (number, text, stamp)


class TelegramTests(unittest.TestCase):
    def test_public_channel_url_validation(self):
        self.assertEqual(telegram_preview_url('https://t.me/Daily_Configs'),
                         'https://t.me/s/daily_configs')
        self.assertIsNone(telegram_preview_url('https://example.com/feed'))
        for url in ('https://t.me/+private', 'https://t.me/s/channel/123',
                    'https://user:secret@t.me/channel'):
            with self.assertRaises(AppError):
                telegram_preview_url(url)

    def test_recent_posts_html_entities_identity_dedup_and_cap(self):
        recent = NOW - timedelta(hours=1)
        html = ('<div>' + uri(99) + '</div>' +
                post(9, uri(1).replace('&', '&amp;'), recent) +
                post(8, '<b>' + uri(1, 'another-remark').replace('&', '&amp;') + '</b>', recent) +
                post(7, 'vless://garbage<br>' + uri(2).replace('&', '&amp;'), recent) +
                post(6, uri(3), NOW - timedelta(days=2)) +
                post(10, uri(4), NOW + timedelta(hours=1)))
        found = collect_telegram_links('https://t.me/channel', lambda url: html, 2, 24, NOW)
        self.assertEqual([parse_link(link).dedup_key for link in found],
                         [parse_link(uri(i)).dedup_key for i in (1, 2)])
        self.assertIn('&sni=test.example', found[0])

    def test_pagination_cutoff_and_uri_in_anchor(self):
        pages = [post(11, '<a href="' + uri(1).replace('&', '&amp;') + '">copy</a>', NOW),
                 post(10, uri(2), NOW - timedelta(hours=23)) + post(9, uri(3), NOW - timedelta(days=3))]
        calls = []
        def fetch(url):
            calls.append(url)
            return pages[len(calls) - 1]
        found = collect_telegram_links('https://t.me/channel', fetch, 50, 24, NOW)
        self.assertEqual(len(found), 2)
        self.assertEqual(calls, ['https://t.me/s/channel', 'https://t.me/s/channel?before=11'])

    def test_restricted_preview_and_invalid_limits_are_explicit_errors(self):
        for html in ('<html>Sign in</html>', post(1, uri(1)).replace(NOW.isoformat(), 'invalid')):
            with self.assertRaises(AppError):
                collect_telegram_links('https://t.me/channel', lambda url: html, now=NOW)
        with self.assertRaises(AppError):
            collect_telegram_links('https://t.me/channel', lambda url: '', limit=0)

    def test_unselected_protocol_does_not_consume_limit(self):
        trojan = 'trojan://password@server.example:443?security=tls&sni=test.example'
        html = post(5, trojan + '<br>' + uri(1))
        links = collect_telegram_links('https://t.me/channel', lambda url: html, limit=1,
                                       now=NOW, protocols={'vless'})
        self.assertEqual(links, [uri(1)])

    def test_pagination_is_bounded_and_repeated_page_stops(self):
        calls = []
        def repeated(url):
            calls.append(url)
            return post(20, 'no configuration')
        self.assertEqual(collect_telegram_links('https://t.me/channel', repeated, now=NOW), [])
        self.assertEqual(len(calls), 2)
        calls.clear()
        def endless(url):
            calls.append(url)
            return post(100-len(calls), 'no configuration')
        with patch('vmess_telegram.MAX_TELEGRAM_PAGES', 3):
            messages = []
            self.assertEqual(collect_telegram_links('https://t.me/channel', endless, now=NOW,
                                                    logger=messages.append), [])
        self.assertEqual(len(calls), 3)
        self.assertTrue(messages)

    def test_collection_tracks_sources_and_failure_does_not_hide_working_feeds(self):
        origins = {}
        messages = []
        with patch('vmess_sources.fetch_source', side_effect=[uri(1), 'Login required']):
            links = collect_links(['https://example.com/feed', 'https://t.me/channel'], '', None,
                                  0, 1, False, messages.append, source_links=origins)
        self.assertEqual(links, {uri(1)})
        self.assertEqual(origins['https://example.com/feed'], {uri(1)})
        self.assertEqual(origins['https://t.me/channel'], set())
        self.assertTrue(any('failed' in message for message in messages))


class PriorityTests(unittest.TestCase):
    def test_quality_then_count_unknown_before_failed_and_dedup(self):
        configs = [parse_link(uri(i)) for i in range(1, 7)]
        keys = {c.raw: c.dedup_key for c in configs}
        sources = {
            'https://example.com/large': {uri(1), uri(2)},
            'https://example.com/small': {uri(1)},
            'https://example.com/unknown': {uri(3)},
            'https://example.com/failed': {uri(4)},
            'https://example.com/lower-rate': {uri(5), uri(6)},
        }
        history = {configs[i-1].dedup_key: {'accepted': accepted, 'score': score}
                   for i, accepted, score in [(1, True, 80), (2, True, 90),
                                              (4, False, 0), (5, True, 65), (6, False, 0)]}
        ordered, rows, memberships = prioritize_configs(configs, sources, keys, history, min_matches=1)
        self.assertEqual([row['source'].rsplit('/', 1)[-1] for row in rows],
                         ['small', 'large', 'lower-rate', 'unknown', 'failed'])
        self.assertEqual([c.address for c in ordered],
                         ['server1.example', 'server2.example', 'server5.example',
                          'server6.example', 'server3.example', 'server4.example'])
        self.assertEqual(len({c.dedup_key for c in ordered}), 6)
        self.assertEqual(memberships[configs[0].dedup_key], [0, 1])
        self.assertEqual(rows[1]['assigned_configs'], 1)

    def test_no_history_smaller_sources_first(self):
        configs = [parse_link(uri(i)) for i in range(1, 4)]
        sources = {'https://example.com/large': {uri(1), uri(2)},
                   'https://example.com/small': {uri(3)}}
        ordered, rows, _ = prioritize_configs(configs, sources, {c.raw: c.dedup_key for c in configs}, {})
        self.assertEqual(ordered[0].address, 'server3.example')
        self.assertTrue(all(row['quality_basis'] == 'unknown' for row in rows))

    def test_one_success_does_not_establish_source_quality(self):
        config = parse_link(uri(1))
        _, rows, _ = prioritize_configs([config], {'https://example.com/feed': {uri(1)}},
            {uri(1): config.dedup_key}, {config.dedup_key: {'accepted': True, 'score': 99}})
        self.assertIsNone(rows[0]['history_acceptance_rate'])
        self.assertEqual(rows[0]['history_accepted'], 1)
        self.assertEqual(rows[0]['minimum_history_matches'], 5)

    def test_history_ignores_wrong_network_expired_interrupted_and_bad_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {'key': parse_link(uri(1)).dedup_key, 'accepted': True, 'score': 80}
            metadata = {'network_name': 'Test', 'interrupted': False,
                        'generated_at_utc': (NOW-timedelta(days=1)).isoformat()}
            for name, changes in [('20261018_010000', {}), ('20261018_020000', {'network_name': 'Other'}),
                                  ('20261018_030000', {'interrupted': True}),
                                  ('20261018_040000', {'generated_at_utc': (NOW-timedelta(days=10)).isoformat()})]:
                (root/(name+'_report.json')).write_text(json.dumps(
                    {'metadata': dict(metadata, **changes), 'all_results': [row]}), encoding='utf-8')
            (root/'20261018_050000_report.json').write_text('invalid', encoding='utf-8')
            messages = []
            history, name = load_recent_results(root, {'network_name': 'Test',
                'allow_insecure_server_cert': False}, messages.append, NOW)
            self.assertEqual(name, '20261018_010000_report.json')
            self.assertTrue(history[row['key']]['accepted'])
            self.assertTrue(messages)
            self.assertEqual(load_recent_results(root, {'network_name': 'Missing'}, lambda s: None, NOW), ({}, ''))

    def test_subscription_label_hides_credentials_but_distinguishes_urls(self):
        first = source_label('https://user:secret@example.com:8443/feed?token=hidden')
        self.assertNotIn('secret', first)
        self.assertNotIn('hidden', first)
        self.assertIn(':8443/feed', first)
        self.assertNotEqual(first, source_label('https://user:other@example.com:8443/feed?token=changed'))

    def test_main_submits_quality_order_and_reports_all_source_memberships(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root/'Test'
            report_dir.mkdir()
            configs = [parse_link(uri(i)) for i in range(1, 10)]
            metadata = {'network_name': 'Test', 'profile': 'default', 'attempts': 3,
                        'deep_test': True, 'min_score': 60, 'test_urls': list(main.DEFAULT_TEST_URLS),
                        'request_timeout': 12.0, 'startup_timeout': 7.0,
                        'tcp_precheck': True, 'tcp_timeout': 3.0, 'interrupted': False,
                        'generated_at_utc': datetime.now(timezone.utc).isoformat()}
            prior = {'metadata': metadata, 'all_results': [
                {'key': cfg.dedup_key, 'accepted': i in (1, 2, 4, 5, 6),
                 'score': 90-i if i in (1, 2, 4, 5, 6) else 0}
                for i, cfg in enumerate(configs, 1)]}
            (report_dir/'20000101_000000_report.json').write_text(json.dumps(prior), encoding='utf-8')
            calls = []
            def fake(cfg, **kwargs):
                calls.append(cfg.address)
                accepted = cfg.address in ['server%d.example' % i for i in (1, 2, 4, 5, 6)]
                return LinkResult(cfg.dedup_key, cfg.raw, cfg.address, cfg.port, cfg.network,
                                  cfg.transport_security, cfg.remark, 80 if accepted else 0,
                                  1.0 if accepted else 0.0, 100.0 if accepted else None, accepted,
                                  protocol=cfg.protocol)
            feeds = ['https://example.com/lower', 'https://example.com/higher']
            bodies = {feeds[0]: '\n'.join(uri(i) for i in (1, 3, 7, 8, 9)),
                      feeds[1]: '\n'.join(uri(i) for i in (1, 2, 4, 5, 6))}
            argv = ['main.py', '--output-dir', str(root), '--network-name', 'Test', '--single-stage', '--workers', '1']
            with patch('sys.argv', argv), patch('main.DEFAULT_SOURCES', feeds), \
                    patch('vmess_sources.fetch_source', side_effect=lambda url, *a: bodies[url]), \
                    patch('main.test_config', side_effect=fake), patch('main.init_db'), \
                    patch('main.record_test_result'), patch('main.find_xray_executable', return_value=Path('xray.exe')), \
                    patch('main.get_xray_version', return_value='test'), patch('main.log'):
                self.assertEqual(main.main(), 0)
            self.assertEqual(calls[:5], ['server%d.example' % i for i in (1, 2, 4, 5, 6)])
            self.assertEqual(set(calls[5:]), {'server%d.example' % i for i in (3, 7, 8, 9)})
            generated = next(p for p in report_dir.glob('*_report.json') if p.name != '20000101_000000_report.json')
            data = json.loads(generated.read_text(encoding='utf-8'))
            rows = data['metadata']['source_priority']
            self.assertEqual(rows[0]['source'], feeds[1])
            self.assertEqual((rows[0]['tested'], rows[0]['accepted']), (5, 5))
            self.assertEqual((rows[1]['tested'], rows[1]['accepted']), (5, 1))
            self.assertEqual(len(data['all_results']), 9)
            shared = next(row for row in data['all_results'] if row['address'] == 'server1.example')
            self.assertEqual(shared['sources'], [feeds[1], feeds[0]])
            self.assertIn('Source test priority', generated.with_suffix('.txt').read_text(encoding='utf-8-sig'))


if __name__ == '__main__':
    unittest.main()
