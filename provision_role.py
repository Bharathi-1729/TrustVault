"""Assign a role through trusted console access; never expose this as HTTP."""

import argparse
import os

from audit import record_audit
from config import Config
from database import connect, transaction, utc_now
from security import ROLES, normalize_email


def assign_role(email, role, config=Config, operator_label=None):
    normalized_email = normalize_email(email)
    if role not in ROLES:
        raise ValueError("Unsupported role.")
    operator = (operator_label or os.environ.get(
        "TRUSTVAULT_OPERATOR_LABEL", "trusted-console-operator"
    )).strip()
    if not operator or len(operator) > 254:
        raise ValueError("Operator label is invalid.")

    connection = connect(config.DATABASE_PATH, config.SQLITE_BUSY_TIMEOUT_MS)
    try:
        with transaction(connection):
            user = connection.execute(
                "SELECT id, role, status FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if user is None or user["status"] != "active":
                raise ValueError("Only existing active accounts may be assigned a role.")
            if user["role"] == role:
                return {"changed": False, "email": normalized_email, "role": role}
            connection.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
                (role, utc_now(), user["id"]),
            )
            record_audit(
                connection,
                action="operator_role_assigned",
                username=operator,
                status="success",
                details={
                    "target_user_id": user["id"],
                    "previous_role": user["role"],
                    "new_role": role,
                    "source": "trusted_console",
                },
            )
        return {"changed": True, "email": normalized_email, "role": role}
    finally:
        connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Set an active account's role using trusted Render console access."
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--role", required=True, choices=sorted(ROLES))
    args = parser.parse_args()
    try:
        result = assign_role(args.email, args.role)
    except ValueError as error:
        parser.error(str(error))
    print(
        "Role unchanged." if not result["changed"] else "Role updated and audit event recorded."
    )
