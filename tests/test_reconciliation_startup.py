import asyncio
from threading import Event
import unittest

from alert2ir.api import create_app
from alert2ir.observability import no_op_observability


class StartupProcessor:
    def __init__(self, *, error=None, release=None):
        self.observability = no_op_observability()
        self.called = Event()
        self.error = error
        self.release = release

    def reconcile_once(self):
        self.called.set()
        if self.release is not None:
            self.release.wait()
        if self.error is not None:
            raise self.error


class StartupReconciliationTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_runs_one_reconciliation_pass_without_blocking_start(self):
        release = Event()
        processor = StartupProcessor(release=release)
        app = create_app(processor)
        async with app.router.lifespan_context(app):
            try:
                called = await asyncio.to_thread(processor.called.wait, 1)
                self.assertTrue(called)
            finally:
                release.set()

    async def test_reconciliation_failure_is_isolated_from_application_lifespan(self):
        processor = StartupProcessor(error=RuntimeError("synthetic failure"))
        app = create_app(processor)
        async with app.router.lifespan_context(app):
            called = await asyncio.to_thread(processor.called.wait, 1)
            self.assertTrue(called)


if __name__ == "__main__":
    unittest.main()
