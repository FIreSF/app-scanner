-- SQLite Schema for Mobile Pentesting Learning Engine

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    target_package TEXT NOT NULL,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    technologies TEXT,
    mode TEXT DEFAULT 'hunt'
);

CREATE TABLE IF NOT EXISTS tested_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    surface TEXT NOT NULL,
    variant_tested TEXT NOT NULL,
    skill_used TEXT,
    result TEXT NOT NULL, -- PASS, VULN, BLOCKED, FP
    evidence_path TEXT,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    target_package TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL, -- Critical, High, Medium, Low, Informational
    state TEXT NOT NULL, -- OBSERVATION, LEAD, HIGH-CONFIDENCE, CONFIRMED, VALIDATED, REPORTABLE
    signature_hash TEXT NOT NULL,
    masvs_category TEXT,
    impact TEXT,
    poc_path TEXT,
    verified INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS triage_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    verdict TEXT NOT NULL, -- ACCEPTED, DUPLICATE, NOT_APPLICABLE, OUT_OF_SCOPE, FALSE_POSITIVE
    comment TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS lessons_learned (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    surface TEXT NOT NULL,
    pattern TEXT NOT NULL,
    lesson TEXT NOT NULL,
    effective_technique TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
