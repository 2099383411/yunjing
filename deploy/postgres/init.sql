CREATE TABLE IF NOT EXISTS scan_tasks (
    id VARCHAR(36) PRIMARY KEY,
    target VARCHAR(512) NOT NULL,
    scan_type VARCHAR(50) DEFAULT 'full',
    status VARCHAR(20) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    result JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(36) PRIMARY KEY,
    task_id VARCHAR(36) NOT NULL REFERENCES scan_tasks(id),
    title VARCHAR(512) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    cve_id VARCHAR(50),
    cvss_score FLOAT,
    target VARCHAR(512) NOT NULL,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    references JSONB DEFAULT '[]',
    tool_source VARCHAR(50),
    confidence FLOAT DEFAULT 0.0,
    discovered_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
    id VARCHAR(36) PRIMARY KEY,
    task_id VARCHAR(36) NOT NULL REFERENCES scan_tasks(id),
    format VARCHAR(10) DEFAULT 'pdf',
    file_path VARCHAR(512),
    summary JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS authorization_logs (
    id VARCHAR(36) PRIMARY KEY,
    target VARCHAR(512) NOT NULL,
    confirmed BOOLEAN DEFAULT FALSE,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_task ON vulnerabilities(task_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_target ON authorization_logs(target);
