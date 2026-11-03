"""Offline checks of actual function bodies, not a Ryu/datapath simulation."""
import ast
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def load_function(filename, name, class_name=None, namespace=None):
    nodes = ast.parse((ROOT / filename).read_text()).body
    if class_name:
        nodes = next(n for n in nodes if isinstance(n, ast.ClassDef)
                     and n.name == class_name).body
    node = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name)
    scope = {} if namespace is None else namespace
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), filename, 'exec'), scope)
    return scope[name]


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.host = (1, 1)
        self.state = SimpleNamespace(strikes={}, last_strike_time={},
            strike_decay=20, base_window=10, base_threshold=5, min_window=4,
            min_threshold=2, window_step=2, threshold_step=1, logger=Mock())
        self.evaluate = load_function('fattree_routing.py',
            '_effective_window_and_threshold', 'FatTreeRouting')

    def test_base_and_repeat(self):
        self.assertEqual(self.evaluate(self.state, self.host, 100), (10, 5))
        self.state.strikes[self.host] = 1
        self.state.last_strike_time[self.host] = 100
        self.assertEqual(self.evaluate(self.state, self.host, 101), (8, 4))

    def test_floor_and_isolation(self):
        self.state.strikes[self.host] = 10
        self.state.last_strike_time[self.host] = 100
        self.assertEqual(self.evaluate(self.state, self.host, 101), (4, 2))
        self.assertEqual(self.evaluate(self.state, (1, 2), 101), (10, 5))

    def test_decay_boundary(self):
        self.state.strikes[self.host] = 1
        self.state.last_strike_time[self.host] = 100
        self.assertEqual(self.evaluate(self.state, self.host, 120), (8, 4))
        self.assertEqual(self.evaluate(self.state, self.host, 121), (10, 5))
        self.assertNotIn(self.host, self.state.strikes)


if __name__ == '__main__':
    unittest.main()
