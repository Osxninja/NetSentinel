"""
NetSentinel - Phase 1 Verification Test Suite
Tests high-throughput ingestion, bounded decoupling buffer,
and asynchronous SQLite WAL batch persistence with 5,000 synthetic packets.
"""

import os
import time
import queue
import asyncio
import tempfile
import pytest
from sqlalchemy import select, func, text

from config import NetSentinelConfig
from database.models import FlowLog
from database.connection import get_async_engine, init_db, get_session_factory
from ingestion.sniffer import PacketSnifferThread
from ingestion.batch_writer import AsyncBatchWriter


@pytest.mark.asyncio
async def test_phase1_ingestion_and_wal_persistence():
    """
    Simulates 5,000 packet flow telemetry records ingested via PacketSnifferThread
    and persisted via AsyncBatchWriter in SQLite WAL mode.
    Verifies:
      1. Zero packet drops in decoupling queue.
      2. Zero SQLITE_BUSY concurrency errors.
      3. Exactly 5,000 records persisted.
      4. Active WAL mode and 5000ms busy_timeout PRAGMAs.
    """
    # 1. Create a temporary SQLite database file
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    test_config = NetSentinelConfig(
        DB_PATH=temp_db_path,
        DATABASE_URL=f"sqlite+aiosqlite:///{temp_db_path}",
        BUFFER_MAXSIZE=10000,
        BATCH_SIZE=250,
        BATCH_FLUSH_INTERVAL=0.5,
    )

    engine = get_async_engine(cfg=test_config)

    try:
        # Initialize schema
        await init_db(engine)

        # 2. Verify SQLite PRAGMAs
        async with engine.connect() as conn:
            journal_res = await conn.execute(text("PRAGMA journal_mode;"))
            journal_mode = journal_res.scalar()
            assert str(journal_mode).lower() == "wal", f"Expected WAL journal mode, got {journal_mode}"

            busy_res = await conn.execute(text("PRAGMA busy_timeout;"))
            busy_timeout = busy_res.scalar()
            assert busy_timeout == 5000, f"Expected 5000ms busy_timeout, got {busy_timeout}"

        # 3. Instantiate bounded decoupling buffer and sniffer
        pkt_queue = queue.Queue(maxsize=test_config.BUFFER_MAXSIZE)
        sniffer = PacketSnifferThread(packet_queue=pkt_queue, prune_layers=False)

        # 4. Instantiate and start AsyncBatchWriter
        writer = AsyncBatchWriter(
            engine=engine,
            packet_queue=pkt_queue,
            batch_size=test_config.BATCH_SIZE,
            flush_interval=test_config.BATCH_FLUSH_INTERVAL,
        )
        writer_task = writer.start()

        # 5. Push 5,000 synthetic packet dictionaries
        num_packets = 5000
        start_time = time.time()

        for i in range(num_packets):
            flow_dict = {
                "timestamp": start_time + (i * 0.001),
                "source_ip": f"192.168.1.{(i % 250) + 1}",
                "destination_ip": "10.0.0.1",
                "source_port": 1024 + (i % 60000),
                "destination_port": 80 if i % 2 == 0 else 443,
                "protocol": "TCP",
                "packet_length": 64 + (i % 1400),
                "tcp_flags": "S" if i % 10 == 0 else "A",
                "window_size": 65535,
            }
            enqueued = sniffer.enqueue_flow_dict(flow_dict)
            assert enqueued, f"Failed to enqueue packet index {i}"

        # Allow writer to process queue
        # Wait until queue is drained
        drain_timeout = 10.0
        drain_start = time.time()
        while not pkt_queue.empty() and (time.time() - drain_start) < drain_timeout:
            await asyncio.sleep(0.05)

        # Stop writer cleanly
        await writer.stop()

        # 6. Verification Assertions
        assert sniffer.dropped_packets == 0, f"Packets were dropped: {sniffer.dropped_packets}"
        assert writer.total_errors == 0, f"Database errors encountered: {writer.total_errors}"
        assert writer.total_inserted == num_packets, f"Expected {num_packets} inserted, got {writer.total_inserted}"

        # Query database to confirm row count
        session_factory = get_session_factory(engine)
        async with session_factory() as session:
            count = await session.scalar(select(func.count(FlowLog.id)))
            assert count == num_packets, f"Database row count mismatch: expected {num_packets}, got {count}"

            # Verify a sample record
            sample = await session.scalar(select(FlowLog).where(FlowLog.id == 1))
            assert sample is not None
            assert sample.destination_ip == "10.0.0.1"
            assert sample.protocol == "TCP"

    finally:
        await engine.dispose()
        # Clean up temporary database files
        for ext in ["", "-wal", "-shm"]:
            path = temp_db_path + ext
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
