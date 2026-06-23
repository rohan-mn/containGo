CREATE TABLE workloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    spiffe_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'quarantined')),
    risk_score INTEGER NOT NULL DEFAULT 0
        CHECK (risk_score >= 0),
    denied_requests INTEGER NOT NULL DEFAULT 0
        CHECK (denied_requests >= 0),
    last_seen_at DATETIME,
    quarantined_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CHECK (
        (status = 'active' AND quarantined_at IS NULL)
        OR
        (status = 'quarantined' AND quarantined_at IS NOT NULL)
    )
);

CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    workload_id INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    decision TEXT NOT NULL
        CHECK (decision IN ('allowed', 'denied')),
    status_code INTEGER NOT NULL
        CHECK (status_code BETWEEN 100 AND 599),
    reason TEXT,
    occurred_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (workload_id)
        REFERENCES workloads(id)
        ON DELETE RESTRICT,
    CHECK (
        decision = 'allowed'
        OR (
            reason IS NOT NULL
            AND length(trim(reason)) > 0
        )
    )
);

CREATE TABLE risk_contributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    security_event_id INTEGER NOT NULL,
    workload_id INTEGER NOT NULL,
    rule TEXT NOT NULL,
    points INTEGER NOT NULL
        CHECK (points > 0),
    reason TEXT NOT NULL
        CHECK (length(trim(reason)) > 0),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (security_event_id)
        REFERENCES security_events(id)
        ON DELETE CASCADE,
    FOREIGN KEY (workload_id)
        REFERENCES workloads(id)
        ON DELETE RESTRICT
);

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workload_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'released')),
    score_at_quarantine INTEGER NOT NULL
        CHECK (score_at_quarantine >= 70),
    quarantined_at DATETIME NOT NULL,
    released_at DATETIME,
    released_by TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (workload_id)
        REFERENCES workloads(id)
        ON DELETE RESTRICT,
    CHECK (
        (
            status = 'open'
            AND released_at IS NULL
            AND released_by IS NULL
        )
        OR
        (
            status = 'released'
            AND released_at IS NOT NULL
            AND released_by IS NOT NULL
            AND length(trim(released_by)) > 0
        )
    )
);

CREATE TABLE incident_reasons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    risk_contribution_id INTEGER,
    rule TEXT NOT NULL,
    points INTEGER NOT NULL
        CHECK (points > 0),
    reason TEXT NOT NULL
        CHECK (length(trim(reason)) > 0),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,
    FOREIGN KEY (risk_contribution_id)
        REFERENCES risk_contributions(id)
        ON DELETE SET NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_spiffe_id TEXT NOT NULL,
    action TEXT NOT NULL
        CHECK (length(trim(action)) > 0),
    target_spiffe_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    occurred_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX one_open_incident_per_workload
    ON incidents(workload_id)
    WHERE status = 'open';

CREATE INDEX security_events_workload_occurred
    ON security_events(workload_id, occurred_at DESC);

CREATE INDEX security_events_decision_occurred
    ON security_events(decision, occurred_at DESC);

CREATE INDEX risk_contributions_workload_created
    ON risk_contributions(workload_id, created_at DESC);

CREATE INDEX incident_reasons_incident
    ON incident_reasons(incident_id, id);

CREATE INDEX audit_log_occurred
    ON audit_log(occurred_at DESC);