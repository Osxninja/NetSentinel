"""
NetSentinel - Asynchronous Batch Persistence Writer
Author: Hardik
Developer / Organization: Hidden Eye Security

Drains normalized packet flow records from the thread-safe decoupling buffer
and executes bulk database inserts in batches every 500ms or 250 records.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import time
import queue
import asyncio
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from config import settings
from database.models import FlowLog
from database.connection import get_session_factory

logger = logging.getLogger("netsentinel.batch_writer")


class AsyncBatchWriter:
    """
    Asynchronous batch writer worker.
    Decouples raw packet capture from SQLite disk I/O, aggregating records
    into chunks and executing bulk `executemany` inserts within WAL mode transactions.
    """

    def __init__(
        self,
        engine: AsyncEngine,
        packet_queue: queue.Queue,
        batch_size: int = settings.BATCH_SIZE,
        flush_interval: float = settings.BATCH_FLUSH_INTERVAL,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    ):
        self.engine = engine
        self.packet_queue = packet_queue
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.session_factory = session_factory or get_session_factory(engine)

        self._stop_requested = False
        self._task: Optional[asyncio.Task] = None

        # Telemetry metrics
        self.total_inserted: int = 0
        self.total_batches: int = 0
        self.total_errors: int = 0

    async def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        """
        Commits a batch of flow dictionaries to the SQLite database.
        """
        if not batch:
            return

        try:
            async with self.session_factory() as session:
                await session.execute(insert(FlowLog), batch)
                await session.commit()
                self.total_inserted += len(batch)
                self.total_batches += 1
                logger.debug("Committed batch of %d records. Total: %d", len(batch), self.total_inserted)
        except Exception as e:
            self.total_errors += 1
            logger.error("Failed to commit batch of %d records: %s", len(batch), e, exc_info=True)
            raise

    async def run(self) -> None:
        """
        Continuous async loop consuming from the packet queue and committing batches.
        """
        logger.info(
            "AsyncBatchWriter started. Batch size: %d, Flush interval: %.2fs",
            self.batch_size,
            self.flush_interval,
        )

        batch: List[Dict[str, Any]] = []
        last_flush_time = time.monotonic()

        while not self._stop_requested:
            # Drain available items without blocking the asyncio loop
            try:
                while len(batch) < self.batch_size:
                    record = self.packet_queue.get_nowait()
                    batch.append(record)
            except queue.Empty:
                pass

            now = time.monotonic()
            time_since_flush = now - last_flush_time

            # Check if threshold reached by count or time
            if batch and (len(batch) >= self.batch_size or time_since_flush >= self.flush_interval):
                await self._flush_batch(batch)
                batch.clear()
                last_flush_time = time.monotonic()

            # Yield control to event loop
            if not batch:
                await asyncio.sleep(0.01)

        # Drain any remaining packets in queue upon shutdown
        logger.info("AsyncBatchWriter draining remaining buffer records...")
        while True:
            try:
                batch.append(self.packet_queue.get_nowait())
                if len(batch) >= self.batch_size:
                    await self._flush_batch(batch)
                    batch.clear()
            except queue.Empty:
                break

        if batch:
            await self._flush_batch(batch)
            batch.clear()

        logger.info(
            "AsyncBatchWriter stopped cleanly. Total committed: %d across %d batches.",
            self.total_inserted,
            self.total_batches,
        )

    def start(self) -> asyncio.Task:
        """
        Spawns the writer as an asyncio background task.
        """
        self._stop_requested = False
        self._task = asyncio.create_task(self.run())
        return self._task

    async def stop(self) -> None:
        """
        Signals the worker to drain remaining records, commit, and cleanly shut down.
        """
        self._stop_requested = True
        if self._task:
            await self._task
