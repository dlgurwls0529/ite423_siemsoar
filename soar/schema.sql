CREATE TABLE IF NOT EXISTS security_incidents (
  id INTEGER PRIMARY KEY,
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
  status TEXT DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS soar_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  action_type TEXT NOT NULL,
  target_type TEXT,
  target_value TEXT,
  mode TEXT DEFAULT 'dry-run',
  status TEXT NOT NULL,
  result_message TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sentry_issue_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  issue_id TEXT,
  comment_body TEXT NOT NULL,
  mode TEXT DEFAULT 'dry-run',
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  channel TEXT NOT NULL,
  message TEXT NOT NULL,
  mode TEXT DEFAULT 'dry-run',
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
