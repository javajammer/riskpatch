-- User-defined skills / context snippets fed into AI correlation as extra LLM context.
-- Examples: security policies, asset criticality, business impact notes, remediation runbooks, compliance requirements.
CREATE TABLE IF NOT EXISTS skills (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Link skills to specific correlation runs for traceability.
CREATE TABLE IF NOT EXISTS skill_uses (
  id INTEGER PRIMARY KEY,
  skill_id INTEGER NOT NULL REFERENCES skills(id),
  correlation_id TEXT NOT NULL,
  used_at TEXT NOT NULL,
  FOREIGN KEY (skill_id) REFERENCES skills(id) ON DELETE CASCADE
);
