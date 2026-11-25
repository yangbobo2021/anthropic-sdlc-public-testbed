"""Assert the documented health and public routes."""
import unittest

from src.service import response


class ServiceTests(unittest.TestCase):
    def test_health(self):
        self.assertEqual(response("/health"), (200, "healthy"))

    def test_root_and_unknown_route(self):
        self.assertEqual(response("/")[0], 200)
        self.assertEqual(response("/missing")[0], 404)
