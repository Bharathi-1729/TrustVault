"""Initialize the schema and optionally issue a one-time registration invite."""

import argparse
from datetime import timedelta

from auth import create_registration_invite
from config import Config, ensure_private_directories
from database import connect, initialize_database, transaction


def seed_database(config=Config, invite_lifetime_hours=None):
    ensure_private_directories(
        {
            "DATABASE_PATH": config.DATABASE_PATH,
            "UPLOAD_FOLDER": config.UPLOAD_FOLDER,
        }
    )
    initialize_database(
        config.DATABASE_PATH,
        config.SQLITE_BUSY_TIMEOUT_MS,
    )
    if invite_lifetime_hours is None:
        return None
    connection = connect(config.DATABASE_PATH, config.SQLITE_BUSY_TIMEOUT_MS)
    try:
        with transaction(connection):
            return create_registration_invite(
                connection,
                lifetime=timedelta(hours=invite_lifetime_hours),
            )
    finally:
        connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize TrustVault safely.")
    parser.add_argument(
        "--create-invite",
        action="store_true",
        help="Create one single-use registration invite and print it once.",
    )
    parser.add_argument(
        "--invite-lifetime-hours",
        type=float,
        default=24,
        help="Lifetime for the invite in hours (default: 24).",
    )
    arguments = parser.parse_args()
    invite = seed_database(
        invite_lifetime_hours=arguments.invite_lifetime_hours
        if arguments.create_invite
        else None
    )
    print("TrustVault database schema is initialized. No default users were created.")
    if invite:
        print(f"Registration invite (store securely; shown only once): {invite}")
