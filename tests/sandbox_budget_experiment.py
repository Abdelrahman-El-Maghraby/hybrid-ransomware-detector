"""Deterministic synthetic latency experiment; fake HTTP and clock, no network.

Run: python -m tests.sandbox_budget_experiment
All budgets are seconds AFTER the existing safety margin. Hypothetical rows
bypass only the submission gate for measurement; no product setting is changed.
"""
import json
import tempfile
from itertools import product
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from core.sandbox import CapeClient
from engine.layers import _sandbox_deadline
from tests.test_sandbox import REPORT, FakeCape, FakeResponse


class DelayedCape(FakeCape):
    def __init__(self, submit, ready, report):
        super().__init__()
        self.t, self.submit_delay, self.ready_delay, self.report_delay = 0.0, submit, ready, report
        self.ready_at = 0.0

    def advance(self, delay, timeout):
        self.t += min(delay, timeout)
        if delay >= timeout:
            raise requests.Timeout("bounded stand-in")

    def post(self, url, files=None, data=None, timeout=None):
        self.advance(self.submit_delay, timeout)
        self.ready_at = self.t + self.ready_delay
        return super().post(url, files, data, timeout)

    def get(self, url, timeout=None):
        if "/tasks/view/" in url:
            self.advance(0.1, timeout)
            return FakeResponse({"data": {"status": "reported" if self.t >= self.ready_at else "running"}})
        self.advance(self.report_delay, timeout)
        return FakeResponse(REPORT)


def experiment():
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "inert.txt"
        path.write_text("inert latency fixture")
        for budget, submit, ready, report in product((5, 14.9, 15, 30), (0.2, 4, 12), (0, 5, 20), (0.2, 4)):
            for gated in (True, False):
                fake = DelayedCape(submit, ready, report)
                client = CapeClient("http://stand-in.invalid", session=fake, poll_seconds=15,
                                    sleep=lambda n: setattr(fake, "t", fake.t + n), clock=lambda: fake.t)
                scanner = SimpleNamespace(time_left=lambda: budget + 30,
                                          config={"scan_timeout_seconds": 300})
                with patch("engine.layers.time.monotonic", lambda: fake.t):
                    deadline, reason = _sandbox_deadline(scanner, client)
                if gated and reason:
                    status, submitted = "not_submitted", False
                else:
                    result = client.analyze(str(path), deadline=budget)
                    status, submitted = result.status, result.submitted
                rows.append(dict(budget=budget, submit=submit, ready=ready, report=report,
                                 gate=gated, status=status, submitted=submitted, elapsed=round(fake.t, 3)))
    return rows


if __name__ == "__main__":
    print(json.dumps(experiment(), indent=2))
