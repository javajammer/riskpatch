-- A campaign is a remediation plan: which work items, which servers, who owns it, when, under which change ticket, with what backout plan.
-- It plans and tracks; it does not deploy anything. Evidence of success still comes from fresh snapshots (see work.verification).
CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    window_start TEXT NOT NULL DEFAULT '',
    window_end TEXT NOT NULL DEFAULT '',
    ticket_id TEXT NOT NULL DEFAULT '',
    backout_plan TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('planned', 'scheduled', 'in_progress', 'completed', 'cancelled')),
    approved_by TEXT NOT NULL DEFAULT '',
    approved_at TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns (workspace_id, status);

CREATE TABLE IF NOT EXISTS campaign_items (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
    PRIMARY KEY (campaign_id, work_item_id)
);

-- What a person reported for each server; the evidence column in the UI is computed from snapshots, never stored here.
CREATE TABLE IF NOT EXISTS campaign_servers (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    asset_id TEXT NOT NULL,
    reported_status TEXT NOT NULL DEFAULT 'planned' CHECK (reported_status IN ('planned', 'attempted', 'updated', 'failed', 'unreachable', 'excepted')),
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (campaign_id, asset_id)
);

-- Which servers each work item was planned for. Kept because after a fix the findings are gone and could not be used to tell.
CREATE TABLE IF NOT EXISTS campaign_targets (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
    asset_id TEXT NOT NULL,
    PRIMARY KEY (campaign_id, work_item_id, asset_id)
);

CREATE TABLE IF NOT EXISTS campaign_events (
    id INTEGER PRIMARY KEY,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_campaign_events_campaign ON campaign_events (campaign_id, id);
