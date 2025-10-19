============================================================================================================

/Users/sreddy/quilr/local_workspace/crew_v2/crew_siem/soc_automation_v2

RUN : 

uv run python crew_execution.py

DEBUG : 
uv run python -m pdb crew_execution.py


============================================================================================================
-- create table for login events
CREATE TABLE IF NOT EXISTS siem_login_events
(
    event_time DateTime64(3),
    tenant_id String,
    user_id String,
    ip String,
    event_type String,        -- "failed" or "success"
    message String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, ip, event_time);

-- insert sample data (example)
INSERT INTO siem_login_events (event_time, tenant_id, user_id, ip, event_type, message) VALUES
('2025-10-18 10:00:00', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:00:20', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:01:05', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:01:30', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:02:10', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:02:40', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:03:00', 't1', 'alice', '10.0.0.5', 'success', 'logged in');




================================================================================================================