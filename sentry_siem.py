#!/usr/bin/env python3
import argparse
import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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
    conn.execute("DELETE FROM sentry_events")
    conn.execute("DELETE FROM security_incidents")
    conn.execute("DELETE FROM sqlite_sequence")
    conn.commit()


def import_sentry_events(conn, events_path):
    count = 0
    with open(events_path, "r", encoding="utf-8") as handle:
        for line in handle:
            event = json.loads(line)
            conn.execute(
                """
                INSERT INTO sentry_events (
                  event_id, issue_id, timestamp, level, title, message,
                  endpoint, method, status_code, source_ip, user_id, session_id,
                  user_agent, payload, exception_type, raw_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("event_id"), event.get("issue_id"), event.get("timestamp"),
                    event.get("level"), event.get("title"), event.get("message"),
                    event.get("endpoint"), event.get("method"), event.get("status_code"),
                    event.get("source_ip"), event.get("user_id"), event.get("session_id"),
                    event.get("user_agent"), event.get("payload"), event.get("exception_type"),
                    json.dumps(event, ensure_ascii=False),
                ),
            )
            count += 1
    conn.commit()
    return count


def classify_events(conn, config):
    incidents = []
    incidents.extend(detect_auth_error_repeated(conn, config))
    incidents.extend(detect_payload_attack(conn, config))
    incidents.extend(detect_admin_path_scan(conn, config))
    incidents.extend(detect_sensitive_error_leak(conn, config))
    incidents.extend(detect_endpoint_error_spike(conn, config))

    saved = []
    seen = set()
    for item in incidents:
        key = (item["incident_type"], item.get("source_ip"), item.get("endpoint"))
        if key in seen:
            continue
        seen.add(key)
        item.update(ai_triage(item))
        incident_id = save_incident(conn, item)
        item["id"] = incident_id
        item["status"] = "open"
        saved.append(item)
    conn.commit()
    return saved


def detect_auth_error_repeated(conn, config):
    threshold = config["thresholds"]["auth_error_repeated"]
    rows = conn.execute(
        """
        SELECT source_ip, COUNT(*) event_count,
               GROUP_CONCAT(DISTINCT issue_id) issue_ids,
               GROUP_CONCAT(DISTINCT endpoint) endpoints
        FROM sentry_events
        WHERE lower(title || ' ' || message || ' ' || exception_type) LIKE '%auth%'
           OR status_code IN (401, 403)
           OR endpoint = '/norder/api/common/sms/request'
        GROUP BY source_ip
        HAVING COUNT(*) >= ?
        """,
        (threshold,),
    ).fetchall()
    return [
        incident(
            "credential_or_auth_attack", "high", row["source_ip"], None, None, None,
            split_csv(row["issue_ids"]), row["event_count"], "로그인/인증 관련 에러 반복",
            {"endpoints": split_csv(row["endpoints"])},
        )
        for row in rows
    ]


def detect_payload_attack(conn, config):
    patterns = config["security_patterns"]["sqli"] + config["security_patterns"]["xss"]
    incidents = []
    for row in conn.execute("SELECT * FROM sentry_events"):
        text = f"{row['endpoint'] or ''} {row['message'] or ''} {row['payload'] or ''}".lower()
        matched = [pattern for pattern in patterns if pattern in text]
        if not matched:
            continue
        severity = "critical" if any(pattern in matched for pattern in config["security_patterns"]["sqli"]) else "high"
        incidents.append(incident(
            "payload_attack", severity, row["source_ip"], row["user_id"], row["session_id"],
            row["endpoint"], [row["issue_id"]], 1, "SQL/XSS 페이로드 포함 요청으로 인한 예외",
            {"matched_patterns": matched, "payload": row["payload"]},
        ))
    return incidents


def detect_admin_path_scan(conn, config):
    threshold = config["thresholds"]["admin_scan_threshold"]
    admin_paths = config["security_patterns"]["admin_paths"]
    grouped = {}
    for row in conn.execute("SELECT * FROM sentry_events WHERE source_ip IS NOT NULL"):
        endpoint = row["endpoint"] or ""
        if any(endpoint.startswith(path) for path in admin_paths):
            grouped.setdefault(row["source_ip"], []).append(row)
    incidents = []
    for source_ip, events in grouped.items():
        if len(events) >= threshold:
            incidents.append(incident(
                "admin_path_scan", "high", source_ip, None, None, None,
                sorted({event["issue_id"] for event in events}), len(events),
                "관리자/숨겨진 경로 스캔",
                {"paths": [event["endpoint"] for event in events]},
            ))
    return incidents


def detect_sensitive_error_leak(conn, config):
    keywords = config["security_patterns"]["sensitive_keywords"]
    incidents = []
    for row in conn.execute("SELECT * FROM sentry_events"):
        text = f"{row['title'] or ''} {row['message'] or ''}".lower()
        matched = [keyword for keyword in keywords if keyword in text]
        leak_indicators = ("exposed", "leak", "token=", "secret=", "authorization:")
        if not matched or not any(indicator in text for indicator in leak_indicators):
            continue
        incidents.append(incident(
            "sensitive_error_leak", "critical", row["source_ip"], row["user_id"], row["session_id"],
            row["endpoint"], [row["issue_id"]], 1, "민감 정보가 포함된 에러 메시지",
            {"matched_keywords": matched},
        ))
    return incidents


def detect_endpoint_error_spike(conn, config):
    threshold = config["thresholds"]["endpoint_error_spike"]
    rows = conn.execute(
        """
        SELECT endpoint, COUNT(*) event_count,
               GROUP_CONCAT(DISTINCT issue_id) issue_ids,
               GROUP_CONCAT(DISTINCT source_ip) source_ips
        FROM sentry_events
        WHERE endpoint IS NOT NULL
          AND (status_code >= 400 OR status_code = 200)
        GROUP BY endpoint
        HAVING COUNT(*) >= ?
        """,
        (threshold,),
    ).fetchall()
    return [
        incident(
            "endpoint_error_spike", "medium", None, None, None, row["endpoint"],
            split_csv(row["issue_ids"]), row["event_count"], "특정 endpoint 오류율 급증",
            {"source_ips": split_csv(row["source_ips"])},
        )
        for row in rows
    ]


def incident(incident_type, severity, source_ip, user_id, session_id, endpoint, issue_ids, event_count, title, evidence):
    return {
        "incident_type": incident_type,
        "severity": severity,
        "source_ip": source_ip,
        "user_id": user_id,
        "session_id": session_id,
        "endpoint": endpoint,
        "sentry_issue_ids": issue_ids,
        "event_count": event_count,
        "title": title,
        "evidence": evidence,
    }


def ai_triage(item):
    score = SEVERITY_ORDER[item["severity"]] * 20 + min(item["event_count"] * 5, 25)
    if item["incident_type"] in ("payload_attack", "sensitive_error_leak"):
        score += 25
    if item["incident_type"] in ("credential_or_auth_attack", "admin_path_scan"):
        score += 15
    score = min(score, 100)
    severity = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    playbook = choose_playbook(item["incident_type"])
    target = item.get("source_ip") or item.get("user_id") or item.get("session_id") or item.get("endpoint") or "unknown"
    return {
        "severity": severity,
        "ai_summary": f"{item['title']} / 대상 {target} / 이벤트 {item['event_count']}건 / Sentry {', '.join(item['sentry_issue_ids'])}",
        "ai_risk_reason": f"위험도 {score}점 (이벤트 수, 유형, 공격 징후 반영)",
        "recommended_playbook": playbook,
    }


def choose_playbook(incident_type):
    if incident_type == "credential_or_auth_attack":
        return "credential_or_auth_attack"
    if incident_type == "payload_attack":
        return "payload_attack"
    if incident_type == "admin_path_scan":
        return "admin_path_scan"
    if incident_type == "sensitive_error_leak":
        return "sensitive_error_leak"
    return "endpoint_error_spike"


def save_incident(conn, item):
    cursor = conn.execute(
        """
        INSERT INTO security_incidents (
          incident_type, severity, source_ip, user_id, session_id, endpoint,
          sentry_issue_ids, event_count, title, ai_summary, ai_risk_reason,
          recommended_playbook, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
        """,
        (
            item["incident_type"], item["severity"], item["source_ip"], item["user_id"],
            item["session_id"], item["endpoint"], json.dumps(item["sentry_issue_ids"], ensure_ascii=False),
            item["event_count"], item["title"], item["ai_summary"], item["ai_risk_reason"],
            item["recommended_playbook"],
        ),
    )
    return cursor.lastrowid


def export_incidents(incidents, output_path):
    with open(output_path, "w", encoding="utf-8") as handle:
        for item in incidents:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    return len(incidents)


def split_csv(value):
    return [item for item in (value or "").split(",") if item]


def main():
    parser = argparse.ArgumentParser(description="Norder Sentry SIEM")
    parser.add_argument("--db", default=str(BASE_DIR / "sentry_siem.db"))
    parser.add_argument("--schema", default=str(BASE_DIR / "schema.sql"))
    parser.add_argument("--config", default=str(BASE_DIR / "config.json"))
    parser.add_argument("--events", default=str(BASE_DIR / "sample_sentry_events.jsonl"))
    parser.add_argument("--output", default=str(BASE_DIR / "incidents.jsonl"))
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    conn = connect(args.db)
    init_db(conn, args.schema)
    event_count = import_sentry_events(conn, args.events)
    incidents = classify_events(conn, load_json(args.config))
    exported = export_incidents(incidents, args.output)

    print(f"Imported {event_count} Sentry events.")
    print(f"Created {len(incidents)} security incidents.")
    print(f"Exported {exported} incidents to {args.output}.")
    for item in incidents:
        print(f"- {item['severity'].upper()} {item['incident_type']}: {item['title']} -> {item['recommended_playbook']}")


if __name__ == "__main__":
    main()
