"""Verify the local audit chain, optionally against a separately protected anchor."""

import argparse
import json
import os

from audit import verify_audit_integrity
from config import Config
from database import connect


def _checkpoint_arguments():
    parser = argparse.ArgumentParser(description="Verify TrustVault audit-chain integrity.")
    parser.add_argument("--expected-head-hash", default=os.environ.get("TRUSTVAULT_AUDIT_EXPECTED_HEAD_HASH"))
    parser.add_argument(
        "--expected-event-count",
        default=os.environ.get("TRUSTVAULT_AUDIT_EXPECTED_EVENT_COUNT"),
    )
    arguments = parser.parse_args()
    if arguments.expected_event_count is not None:
        try:
            arguments.expected_event_count = int(arguments.expected_event_count)
        except ValueError as error:
            parser.error("--expected-event-count must be an integer")
    return arguments


def main():
    arguments = _checkpoint_arguments()
    connection = connect(Config.DATABASE_PATH, Config.SQLITE_BUSY_TIMEOUT_MS)
    try:
        report = verify_audit_integrity(
            connection,
            expected_head_hash=arguments.expected_head_hash,
            expected_event_count=arguments.expected_event_count,
        )
    finally:
        connection.close()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
