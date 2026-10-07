# -*- coding: utf-8 -*-
import gc
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from vmess_pipeline import run_tests
from vmess_types import AppError, LinkResult, ProbeResult, parse_link


def config(i):
    return parse_link('trojan://pass@node%d.example.com:443#test' % i)


def result(cfg, success=False, accepted=False, score=0, stage=''):
    return LinkResult(
        cfg.dedup_key, cfg.raw, cfg.address, cfg.port, cfg.network,
        cfg.transport_security, cfg.remark, score, float(success),
        100.0 if success else None, accepted, stage,
        probes=[ProbeResult('https://test', success, 204 if success else None, 100.0, 0)],
        protocol=cfg.protocol)


class PipelineTests(unittest.TestCase):
    def test_low_screen_score_promotes_and_only_full_result_is_published(self):
        good, bad = config(1), config(2)
        saved, calls = [], []
        def screen(cfg):
            return result(cfg, cfg == good, score=1, stage='request')
        def full(cfg):
            calls.append(cfg)
            return result(cfg, True, True, 80)
        interrupted, metrics = run_tests(
            [good, bad], screen, lambda c, r: saved.append(r), 2, full, 1)
        self.assertFalse(interrupted)
        self.assertEqual(calls, [good])
        self.assertEqual(len(saved), 2)
        self.assertEqual([r.score for r in saved if r.accepted], [80])
        self.assertEqual(metrics['screening_completed'], 2)
        self.assertEqual(metrics['quality_completed'], 1)
        self.assertEqual(metrics['final_results'], 2)

    def test_full_failure_overrides_screen_success(self):
        saved = []
        run_tests([config(1)], lambda c: result(c, True, True, 99),
                  lambda c, r: saved.append(r), 1, lambda c: result(c, stage='request'), 1)
        self.assertEqual(len(saved), 1)
        self.assertFalse(saved[0].accepted)

    def test_no_successful_https_cannot_be_accepted(self):
        saved = []
        run_tests([config(1)], lambda c: result(c, accepted=True),
                  lambda c, r: saved.append(r), 1,
                  lambda c: self.fail('Failed screen promoted'), 1)
        self.assertFalse(saved[0].accepted)

    def test_quality_overlaps_next_screening(self):
        good, slow = config(1), config(2)
        started = threading.Event()
        def screen(cfg):
            if cfg == slow and not started.wait(2):
                raise AssertionError('Quality did not overlap screening')
            return result(cfg, cfg == good)
        def full(cfg):
            started.set()
            return result(cfg, True, True, 80)
        run_tests([good, slow], screen, lambda c, r: None, 1, full, 1)
        self.assertTrue(started.is_set())

    def test_bounded_backlog_and_worker_limits(self):
        saved, lock = [], threading.Lock()
        active, peak = {'screen': 0, 'full': 0}, {'screen': 0, 'full': 0}
        def inputs():
            for i in range(80):
                self.assertLessEqual(i + 1 - len(saved), 5)
                yield config(i)
        def timed(stage, delay, cfg):
            with lock:
                active[stage] += 1
                peak[stage] = max(peak[stage], active[stage])
            time.sleep(delay)
            with lock:
                active[stage] -= 1
            return result(cfg, True, stage == 'full', 80)
        _, metrics = run_tests(inputs(), lambda c: timed('screen', .001, c),
                               lambda c, r: saved.append(r), 3,
                               lambda c: timed('full', .005, c), 2)
        self.assertEqual(len(saved), 80)
        self.assertEqual(len({r.key for r in saved}), 80)
        self.assertLessEqual(peak['screen'], 3)
        self.assertEqual(peak['full'], 2)
        self.assertEqual(metrics['quality_completed'], 80)

    def test_worker_exception_becomes_failure(self):
        def broken(cfg):
            raise AppError('invalid config')
        saved = []
        run_tests([config(1)], broken, lambda c, r: saved.append(r), 1,
                  lambda c: self.fail('Failed screen promoted'), 1)
        self.assertEqual(saved[0].error_stage, 'worker')
        self.assertIn('invalid config', saved[0].error)

    def test_single_stage_does_not_repeat_tests(self):
        saved, calls = [], []
        def full(cfg):
            calls.append(cfg)
            return result(cfg, True, True, 80)
        _, metrics = run_tests([config(i) for i in range(7)], full,
                               lambda c, r: saved.append(r), 2)
        self.assertEqual(len(calls), 7)
        self.assertEqual(len(saved), 7)
        self.assertEqual(metrics['screening_completed'], 0)
        self.assertEqual(metrics['quality_completed'], 7)

    def test_interrupt_stops_both_pools_and_keeps_final_result(self):
        saved = []
        def save(cfg, res):
            saved.append(res)
            raise KeyboardInterrupt
        with patch('vmess_pipeline.stop_all_processes') as stop:
            interrupted, _ = run_tests(
                [config(i) for i in range(10)], lambda c: result(c, True), save,
                1, lambda c: result(c, True, True, 80), 1, logger=lambda s: None)
        self.assertTrue(interrupted)
        stop.assert_called_once()
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0].accepted)

    def test_persistence_failure_is_not_swallowed(self):
        def save(cfg, res):
            raise OSError('disk full')
        with patch('vmess_pipeline.stop_all_processes') as stop:
            with self.assertRaisesRegex(OSError, 'disk full'):
                run_tests([config(i) for i in range(10)], lambda c: result(c), save, 2)
            stop.assert_called_once()

    def test_empty_input_and_invalid_counts(self):
        _, metrics = run_tests([], lambda c: result(c), lambda c, r: None, 1)
        self.assertEqual(metrics['final_results'], 0)
        for workers, quality_workers in ((0, 1), (17, 1), (1, 0), (1, 17)):
            with self.assertRaises(AppError):
                run_tests([], lambda c: result(c), lambda c, r: None,
                          workers, quality_workers=quality_workers)


class MainPipelineTests(unittest.TestCase):
    def run_main(self, extra):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / 'configs.txt'
            seed.write_text(config(1).raw + '\n' + config(2).raw, encoding='utf-8')
            calls = []
            def fake(cfg, **kwargs):
                calls.append((cfg, kwargs))
                good = cfg.address == config(1).address
                screening = kwargs['min_score'] == 0
                return result(cfg, good, good and not screening,
                              1 if screening else (80 if good else 0),
                              '' if good else 'request')
            argv = ['main.py', '--seed-file', str(seed), '--no-default-sources',
                    '--output-dir', str(root / 'output'), '--network-name', 'Test'] + extra
            with patch('sys.argv', argv), patch('main.test_config', side_effect=fake), \
                    patch('main.find_xray_executable', return_value=Path('xray.exe')), \
                    patch('main.get_xray_version', return_value='Xray test'), patch('main.log'):
                self.assertEqual(main.main(), 0)
            payload = json.loads(next((root / 'output').rglob('*_report.json')).read_text('utf-8'))
            with sqlite3.connect(str(root / 'output' / 'proxy_history.db')) as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM test_records').fetchone()[0], 2)
                self.assertEqual(conn.execute('SELECT max(total_tests) FROM configs').fetchone()[0], 1)
            conn.close()
            gc.collect()  # Release legacy SQLite transaction contexts before Windows cleanup.
            self.assertEqual(payload['tested_count'], 2)
            self.assertEqual(payload['accepted_count'], 1)
            text = next((root / 'output').rglob('*_report.txt')).read_text('utf-8-sig')
            self.assertIn('Testing elapsed:', text)
            return calls, payload

    def test_default_pipeline_and_full_test_settings(self):
        calls, payload = self.run_main([])
        self.assertEqual(len(calls), 3)
        metadata = payload['metadata']
        self.assertEqual(metadata['testing_mode'], 'two-stage')
        self.assertEqual(metadata['workers'], 8)
        self.assertEqual(metadata['quality_workers'], 2)
        full = [kwargs for _, kwargs in calls if kwargs['deep_test']]
        self.assertEqual(len(full), 1)
        self.assertEqual(full[0]['attempts'], 3)
        self.assertEqual(full[0]['min_score'], 60)
        self.assertEqual(full[0]['request_timeout'], 12.0)

    def test_single_stage_and_no_deep_keep_original_defaults(self):
        for flag in ('--single-stage', '--no-deep-test'):
            calls, payload = self.run_main([flag])
            self.assertEqual(len(calls), 2)
            self.assertEqual(payload['metadata']['testing_mode'], 'single-stage')
            self.assertEqual(payload['metadata']['workers'], 4)
            self.assertTrue(all(k['attempts'] == 3 for _, k in calls))
            self.assertTrue(all(k['deep_test'] == (flag == '--single-stage') for _, k in calls))

    def test_explicit_workers_and_conservative_profile(self):
        _, payload = self.run_main(['--profile', 'mci'])
        self.assertEqual(payload['metadata']['workers'], 3)
        _, payload = self.run_main(['--workers', '6', '--quality-workers', '1'])
        self.assertEqual(payload['metadata']['workers'], 6)
        self.assertEqual(payload['metadata']['quality_workers'], 1)


if __name__ == '__main__':
    unittest.main()
