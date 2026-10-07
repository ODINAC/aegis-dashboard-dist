#!/bin/bash
set -e

# Get admin password from secret
AEGIS_DASHBOARD_DB_PASSWORD=$(cat /run/secrets/aegis_dashboard_db_password)

# Create user and database
psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER}" <<EOF
CREATE USER ${AEGIS_DASHBOARD_DB_USER} WITH PASSWORD '${AEGIS_DASHBOARD_DB_PASSWORD}';
CREATE DATABASE ${AEGIS_DASHBOARD_DB_NAME} OWNER ${AEGIS_DASHBOARD_DB_USER};
REVOKE ALL ON DATABASE ${AEGIS_DASHBOARD_DB_NAME} FROM PUBLIC;
GRANT CONNECT ON DATABASE ${AEGIS_DASHBOARD_DB_NAME} TO ${AEGIS_DASHBOARD_DB_USER};
EOF

# Grant user privileges
psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER}" -d "${AEGIS_DASHBOARD_DB_NAME}" <<EOF
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO ${AEGIS_DASHBOARD_DB_USER};
EOF

# Creata tables and indexes
psql -v ON_ERROR_STOP=1 -U "${AEGIS_DASHBOARD_DB_USER}" -d "${AEGIS_DASHBOARD_DB_NAME}" <<'EOF'

CREATE TABLE IF NOT EXISTS organisations (
    org_id VARCHAR(10) NOT NULL,
    org_name VARCHAR(64) NOT NULL,
    PRIMARY KEY (org_id)
);

CREATE TABLE IF NOT EXISTS environments (
    org_id VARCHAR(10) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    contact1_name VARCHAR(64),
    contact1_email VARCHAR(64),
    contact1_phone VARCHAR(64),
    contact2_name VARCHAR(64),
    contact2_email VARCHAR(64),
    contact2_phone VARCHAR(64),
    PRIMARY KEY (org_id, environment),
    FOREIGN KEY (org_id) REFERENCES organisations(org_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    org_id VARCHAR(10) NOT NULL,
    report_date DATE NOT NULL,
    project_ref VARCHAR(16) NOT NULL,
    project_name VARCHAR(256) NOT NULL,
    project_type VARCHAR(16) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    category VARCHAR(64) NOT NULL,
    finding_ref VARCHAR(20) NOT NULL,
    finding_name VARCHAR(256) NOT NULL,
    probability INT NOT NULL CHECK (probability BETWEEN 0 AND 5),
    impact INT NOT NULL CHECK (impact BETWEEN 0 AND 5),
    risk VARCHAR(10) GENERATED ALWAYS AS (
        CASE
            WHEN probability = 0 AND impact = 0 THEN 'Info'
            WHEN probability = 0 AND impact = 1 THEN 'Info'
            WHEN probability = 0 AND impact = 2 THEN 'Info'
            WHEN probability = 0 AND impact = 3 THEN 'Info'
            WHEN probability = 0 AND impact = 4 THEN 'Info'
            WHEN probability = 0 AND impact = 5 THEN 'Info'
            WHEN probability = 1 AND impact = 0 THEN 'Info'
            WHEN probability = 1 AND impact = 1 THEN 'Low'
            WHEN probability = 1 AND impact = 2 THEN 'Low'
            WHEN probability = 1 AND impact = 3 THEN 'Low'
            WHEN probability = 1 AND impact = 4 THEN 'Medium'
            WHEN probability = 1 AND impact = 5 THEN 'Medium'
            WHEN probability = 2 AND impact = 0 THEN 'Info'
            WHEN probability = 2 AND impact = 1 THEN 'Low'
            WHEN probability = 2 AND impact = 2 THEN 'Low'
            WHEN probability = 2 AND impact = 3 THEN 'Medium'
            WHEN probability = 2 AND impact = 4 THEN 'Medium'
            WHEN probability = 2 AND impact = 5 THEN 'High'
            WHEN probability = 3 AND impact = 0 THEN 'Info'
            WHEN probability = 3 AND impact = 1 THEN 'Low'
            WHEN probability = 3 AND impact = 2 THEN 'Medium'
            WHEN probability = 3 AND impact = 3 THEN 'Medium'
            WHEN probability = 3 AND impact = 4 THEN 'High'
            WHEN probability = 3 AND impact = 5 THEN 'High'
            WHEN probability = 4 AND impact = 0 THEN 'Info'
            WHEN probability = 4 AND impact = 1 THEN 'Medium'
            WHEN probability = 4 AND impact = 2 THEN 'Medium'
            WHEN probability = 4 AND impact = 3 THEN 'High'
            WHEN probability = 4 AND impact = 4 THEN 'High'
            WHEN probability = 4 AND impact = 5 THEN 'Critical'
            WHEN probability = 5 AND impact = 0 THEN 'Info'
            WHEN probability = 5 AND impact = 1 THEN 'Medium'
            WHEN probability = 5 AND impact = 2 THEN 'High'
            WHEN probability = 5 AND impact = 3 THEN 'High'
            WHEN probability = 5 AND impact = 4 THEN 'Critical'
            WHEN probability = 5 AND impact = 5 THEN 'Critical'
            ELSE ''
        END
    ) STORED,
    found_date DATE NOT NULL,
    last_assessed_date DATE NOT NULL,
    resolved_date DATE NULL,
    owasp VARCHAR(256) NULL,
    cwe VARCHAR(256) NULL,
    fix_applied_date DATE NULL,
    finding_status VARCHAR(32) GENERATED ALWAYS AS (
        CASE
            WHEN resolved_date IS NOT NULL THEN 'Resolved'
            WHEN fix_applied_date IS NOT NULL THEN 'Fix Applied'
            ELSE 'Open'
        END
    ) STORED,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    report VARCHAR(256) NOT NULL,
    PRIMARY KEY (org_id, environment, project_ref, finding_ref),
    FOREIGN KEY (org_id) REFERENCES organisations(org_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings_comments (
    id SERIAL NOT NULL,
    org_id VARCHAR(10) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    project_ref VARCHAR(16) NOT NULL,
    finding_ref VARCHAR(20) NOT NULL,
    comment_date TIMESTAMPTZ NOT NULL,
    comment_user VARCHAR(64) NOT NULL,
    comment_text VARCHAR(4096) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (org_id, environment, project_ref, finding_ref) REFERENCES findings(org_id, environment, project_ref, finding_ref) ON DELETE CASCADE
);

CREATE INDEX idx_findings_comment ON findings_comments (org_id, environment, finding_ref);

CREATE TABLE IF NOT EXISTS projects (
    org_id VARCHAR(10) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    project_ticket VARCHAR(16) NULL,
    project_type VARCHAR(16) NOT NULL,
    project_ref VARCHAR(16) NOT NULL,
    project_name VARCHAR(256) NOT NULL,
    project_description TEXT NULL,
    contract_reference VARCHAR(64) NULL,
    ready_date DATE NULL,
    live_date DATE NULL,
    source_code_included BOOLEAN NULL,
    remote_assessment BOOLEAN NULL,
    project_start_date DATE NULL,
    project_report_date DATE NULL,
    project_days INT NULL,
    project_lead VARCHAR(64) NULL,
    project_status VARCHAR(32) NOT NULL,
    contact1_name VARCHAR(64) NULL,
    contact1_email VARCHAR(64) NULL,
    contact1_phone VARCHAR(64) NULL,
    contact2_name VARCHAR(64) NULL,
    contact2_email VARCHAR(64) NULL,
    contact2_phone VARCHAR(64) NULL,
    PRIMARY KEY (org_id, environment, project_ref),
    FOREIGN KEY (org_id) REFERENCES organisations(org_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects_comments (
    id SERIAL NOT NULL,
    org_id VARCHAR(10) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    project_ref VARCHAR(16) NOT NULL,
    comment_date TIMESTAMPTZ NOT NULL,
    comment_user VARCHAR(64) NOT NULL,
    comment_text VARCHAR(4096) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (org_id, environment, project_ref) REFERENCES projects(org_id, environment, project_ref) ON DELETE CASCADE
);

CREATE INDEX idx_projects_comment ON projects_comments (org_id, environment, project_ref);

CREATE TABLE IF NOT EXISTS file_checksums (
    org_id VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    size BIGINT NOT NULL,
    mtime DOUBLE PRECISION NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, path),
    FOREIGN KEY (org_id) REFERENCES organisations(org_id) ON DELETE CASCADE
);

-- Principals and membership. Authorisation is core-owned (the shared IdP does
-- not issue `groups`): every user is pre-provisioned, and org access is an
-- explicit user_orgs row. Mirrors the sibling aegis (Rust/SeaORM) schema.
CREATE TABLE IF NOT EXISTS users (
    id UUID NOT NULL DEFAULT uuidv7(),
    sub VARCHAR(64) UNIQUE,
    email VARCHAR(255) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE (email)
);

CREATE TABLE IF NOT EXISTS user_orgs (
    user_id UUID NOT NULL,
    org_id VARCHAR(10) NOT NULL,
    PRIMARY KEY (user_id, org_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (org_id) REFERENCES organisations(org_id) ON DELETE CASCADE
);

-- Per-user API keys (machine clients); only the SHA-256 hash is stored.
CREATE TABLE IF NOT EXISTS user_keys (
    id UUID NOT NULL DEFAULT uuidv7(),
    user_id UUID NOT NULL,
    key_hash CHAR(64) NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    CONSTRAINT uq_user_keys_key_hash UNIQUE (key_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE OR REPLACE VIEW findings_latest AS
SELECT DISTINCT ON (org_id, environment, finding_ref) *
FROM findings
ORDER BY org_id, environment, finding_ref, last_assessed_date DESC, project_ref DESC;

-- Migration ledger (see core/migrations/ and core/app/migrations.py, which
-- core runs on startup). This init script always creates the latest schema, so
-- every existing migration is pre-recorded here as applied and the startup
-- runner is a no-op on a fresh database. IMPORTANT: when you add a migration
-- AND fold its schema into this file, add its filename stem to the seed list
-- below.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    VARCHAR PRIMARY KEY,
    applied_at BIGINT NOT NULL
);

INSERT INTO schema_migrations (version, applied_at) VALUES
    ('2026-06-19-widen-project-name', extract(epoch from now())::bigint),
    ('2026-07-06-add-file-checksums', extract(epoch from now())::bigint),
    ('2026-09-27-add-users-and-user-orgs', extract(epoch from now())::bigint),
    ('2026-09-27-add-user-keys', extract(epoch from now())::bigint)
ON CONFLICT (version) DO NOTHING;
EOF