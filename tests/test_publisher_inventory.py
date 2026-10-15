"""Offline, complete PR inventory before any status writes."""
import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class PublisherInventoryTests(unittest.TestCase):
    def setUp(self):
        driver = types.ModuleType('psycopg2')
        extras = types.ModuleType('psycopg2.extras')
        driver.connect = mock.Mock(side_effect=AssertionError('no live database'))
        extras.RealDictCursor = object
        driver.extras = extras
        with mock.patch.dict(sys.modules, {'psycopg2': driver, 'psycopg2.extras': extras}):
            self.module = runpy.run_path(str(ROOT / 'bin/codestra-github-statusd'), run_name='offline_inventory')

    def pr(self, number):
        return dict(number=number, head=dict(ref='fixture', sha='a' * 40),
                    base=dict(ref='main'), html_url='https://example.invalid/pr/' + str(number))

    def collect(self, pages):
        collector = self.module['open_prs']
        reader = mock.Mock(side_effect=pages)
        with mock.patch.dict(collector.__globals__, gh_json=reader):
            result = collector('Middleware-')
        return result, reader

    def test_all_pages_collected_before_return(self):
        result, read = self.collect([[self.pr(i) for i in range(1, 101)], [self.pr(101)]])
        self.assertEqual(len(result), 101)
        self.assertIn('page=2', read.call_args.args[0])

    def test_exact_full_page_requires_terminal_page(self):
        result, read = self.collect([[self.pr(i) for i in range(1, 101)], []])
        self.assertEqual(len(result), 100)
        self.assertEqual(read.call_count, 2)

    def test_duplicate_or_malformed_inventory_denies(self):
        for response in ({'items': []}, [None], [self.pr(1), self.pr(1)],
                         [dict(self.pr(1), head={'ref': 'fixture', 'sha': 'bad'})]):
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                self.collect([response])

    def test_incomplete_inventory_never_validates_or_posts_partial_results(self):
        first = [self.pr(i) for i in range(1, 101)]
        scenarios = ([first, RuntimeError('page failed')], [first, [None]],
                     [first, [self.pr(1)]],
                     [[self.pr(page * 100 + i + 1) for i in range(100)] for page in range(100)])
        for pages in scenarios:
            with self.subTest(pages=len(pages)):
                main = self.module['main']
                read = mock.Mock(side_effect=pages)
                validate, post = mock.Mock(), mock.Mock()
                with mock.patch.dict(main.__globals__, {
                    'psycopg2': types.SimpleNamespace(connect=lambda *_: object()),
                    'aliases': lambda *_: [('Middleware-', 'Middleware-', 'testing', '/unused')],
                    'gh_json': read, 'validate': validate, 'post': post,
                }), mock.patch('os.path.isdir', return_value=True):
                    with self.assertRaises(SystemExit) as exit_result:
                        main()
                self.assertEqual(exit_result.exception.code, 1)
                validate.assert_not_called()
                post.assert_not_called()

    def test_pagination_exhaustion_denies_partial_inventory(self):
        collector = self.module['open_prs']
        pages = [[self.pr(page * 100 + i + 1) for i in range(100)] for page in range(100)]
        read = mock.Mock(side_effect=pages)
        with mock.patch.dict(collector.__globals__, gh_json=read):
            with self.assertRaisesRegex(RuntimeError, 'pagination limit'):
                collector('Middleware-')
        self.assertEqual(read.call_count, 100)

    def test_later_page_rate_limit_propagates_without_retry(self):
        collector = self.module['open_prs']
        read = mock.Mock(side_effect=[[self.pr(i) for i in range(1, 101)], self.module['RateLimited']('throttled')])
        with mock.patch.dict(collector.__globals__, gh_json=read):
            with self.assertRaises(self.module['RateLimited']):
                collector('Middleware-')
        self.assertEqual(read.call_count, 2)

    def test_main_evaluates_pr_on_second_page_after_complete_inventory(self):
        main = self.module['main']
        read = mock.Mock(side_effect=[[self.pr(i) for i in range(1, 101)], [self.pr(101)]])
        validate = mock.Mock(return_value=(False, 'fixture denial'))
        post = mock.Mock()
        with mock.patch.dict(main.__globals__, {
            'psycopg2': types.SimpleNamespace(connect=lambda *_: object()),
            'aliases': lambda *_: [('Middleware-', 'Middleware-', 'testing', '/unused')],
            'gh_json': read, 'validate': validate, 'post': post,
        }), mock.patch('os.path.isdir', return_value=True), mock.patch('builtins.print'):
            with self.assertRaises(SystemExit) as exit_result:
                main()
        self.assertEqual(exit_result.exception.code, 0)
        self.assertEqual(validate.call_count, 101)
        self.assertEqual(post.call_count, 101)
        self.assertEqual(post.call_args.args[-1], self.pr(101)['html_url'])
