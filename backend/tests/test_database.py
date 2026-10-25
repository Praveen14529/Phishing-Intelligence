import asyncio
import unittest
from datetime import datetime

from services import database


class DatabaseStatsTests(unittest.TestCase):
    def test_stats_include_all_memory_history(self):
        original_store = database._memory_store
        database._memory_store = [
            {
                "query_domain": f"domain-{index}.example",
                "overall_risk_level": "high",
                "high_risk_count": 1,
                "total_variants_existing": 2,
                "scanned_at": datetime(2026, 1, 1),
            }
            for index in range(101)
        ]
        try:
            stats = asyncio.run(database.get_stats())
        finally:
            database._memory_store = original_store

        self.assertEqual(stats["total_scans"], 101)
        self.assertEqual(stats["high_risk_domains"], 101)
        self.assertEqual(stats["total_domains_detected"], 202)


if __name__ == "__main__":
    unittest.main()