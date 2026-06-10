CREATE TABLE IF NOT EXISTS sentry_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  issue_id TEXT,
  timestamp TEXT NOT NULL,
  level TEXT,
  title TEXT,
  message TEXT,
  endpoint TEXT,
  method TEXT,
  status_code INTEGER,
  source_ip TEXT,
  user_id TEXT,
  session_id TEXT,
  user_agent TEXT,
  payload TEXT,
  exception_type TEXT,
  raw_event TEXT
);

CREATE TABLE IF NOT EXISTS security_incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  source_ip TEXT,
  user_id TEXT,
  session_id TEXT,
  endpoint TEXT,
  sentry_issue_ids TEXT,
  event_count INTEGER DEFAULT 1,
  title TEXT NOT NULL,
  ai_summary TEXT,
  ai_risk_reason TEXT,
  recommended_playbook TEXT,
  status TEXT DEFAULT 'open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
