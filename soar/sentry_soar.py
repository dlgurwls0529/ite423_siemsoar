import argparse
import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def init_db(conn, schema_path):
    with open(schema_path, "r", encoding="utf-8") as handle:
        conn.executescript(handle.read())
    for table in ["security_incidents", "soar_actions", "sentry_issue_comments", "notifications"]:
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence")
    conn.commit()


def import_incidents(conn, incidents_path):
    count = 0
    with open(incidents_path, "r", encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            conn.execute(
                """
                INSERT INTO security_incidents (
                  id, incident_type, severity, source_ip, user_id, session_id,
                  endpoint, sentry_issue_ids, event_count, title, ai_summary,
                  ai_risk_reason, recommended_playbook, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["id"], item["incident_type"], item["severity"], item.get("source_ip"),
                    item.get("user_id"), item.get("session_id"), item.get("endpoint"),
                    json.dumps(item.get("sentry_issue_ids", []), ensure_ascii=False),
                    item.get("event_count", 1), item["title"], item.get("ai_summary"),
                    item.get("ai_risk_reason"), item.get("recommended_playbook"), item.get("status", "open"),
                ),
            )
            count += 1
    conn.commit()
    return count


def run_soar(conn, config):
    incidents = conn.execute("SELECT * FROM security_incidents WHERE status = 'open' ORDER BY id").fetchall()
    for incident in incidents:
        actions = config["playbooks"].get(incident["recommended_playbook"], ["notify_security_channel"])
        for action_type in actions:
            execute_action(conn, incident, action_type)
        conn.execute("UPDATE security_incidents SET status = 'dry_run_completed' WHERE id = ?", (incident["id"],))
    conn.commit()
    return len(incidents)


def execute_action(conn, incident, action_type):
    if action_type == "notify_security_channel":
        message = f"[{incident['severity'].upper()}] {incident['title']} - {incident['ai_summary']}"
        conn.execute(
            "INSERT INTO notifications (incident_id, channel, message, status) VALUES (?, ?, ?, ?)",
            (incident["id"], "slack_or_discord", message, "dry_run_created"),
        )
        action(conn, incident, action_type, "channel", "slack_or_discord", "Notification record created")
    elif action_type == "comment_sentry_issue":
        issue_ids = json.loads(incident["sentry_issue_ids"] or "[]")
        comment = build_comment(incident)
        for issue_id in issue_ids:
            conn.execute(
                "INSERT INTO sentry_issue_comments (incident_id, issue_id, comment_body, status) VALUES (?, ?, ?, ?)",
                (incident["id"], issue_id, comment, "dry_run_created"),
            )
        action(conn, incident, action_type, "sentry_issue", ",".join(issue_ids), "Sentry issue response note recorded")
    elif action_type == "dry_run_ip_block":
        target = incident["source_ip"] or "unknown_ip"
        action(conn, incident, action_type, "ip", target, "IP block candidate recorded")
    else:
        target = incident["endpoint"] or incident["incident_type"]
        action(conn, incident, action_type, "task", target, f"{action_type} task recorded")


def build_comment(incident):
    return (
        "[Security response note]\n"
        f"- Incident: {incident['title']}\n"
        f"- Severity: {incident['severity']}\n"
        f"- Summary: {incident['ai_summary']}\n"
        f"- Risk reason: {incident['ai_risk_reason']}\n"
        f"- Recommended playbook: {incident['recommended_playbook']}\n"
        "- Action mode: dry-run\n"
    )


def action(conn, incident, action_type, target_type, target_value, message):
    conn.execute(
        """
        INSERT INTO soar_actions (
          incident_id, action_type, target_type, target_value, mode, status, result_message
        ) VALUES (?, ?, ?, ?, 'dry-run', 'dry_run_created', ?)
        """,
        (incident["id"], action_type, target_type, target_value, message),
    )


def print_summary(conn):
    print("\n== SOAR Dry-run Actions ==")
    for row in conn.execute("SELECT incident_id, action_type, target_type, target_value, status, result_message FROM soar_actions ORDER BY id"):
        print(f"[incident {row['incident_id']}] {row['action_type']} {row['target_type']}={row['target_value']} {row['status']} - {row['result_message']}")

    print("\n== Sentry Issue Comments ==")
    for row in conn.execute("SELECT incident_id, issue_id, status FROM sentry_issue_comments ORDER BY id"):
        print(f"[incident {row['incident_id']}] issue={row['issue_id']} status={row['status']}")

    print("\n== Notifications ==")
    for row in conn.execute("SELECT incident_id, channel, status FROM notifications ORDER BY id"):
        print(f"[incident {row['incident_id']}] channel={row['channel']} status={row['status']}")


def main():
    parser = argparse.ArgumentParser(description="Norder Sentry SOAR")
    parser.add_argument("--db", default=str(BASE_DIR / "sentry_soar.db"))
    parser.add_argument("--schema", default=str(BASE_DIR / "schema.sql"))
    parser.add_argument("--config", default=str(BASE_DIR / "config.json"))
    parser.add_argument("--incidents", default=str(BASE_DIR / "sample_incidents.jsonl"))
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    conn = connect(args.db)
    init_db(conn, args.schema)
    imported = import_incidents(conn, args.incidents)
    handled = run_soar(conn, load_json(args.config))

    print(f"Imported {imported} incidents.")
    print(f"SOAR dry-run handled {handled} incidents.")
    print_summary(conn)


if __name__ == "__main__":
    main()
