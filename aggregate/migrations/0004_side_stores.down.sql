DROP TABLE IF EXISTS ai_transcripts;

DROP INDEX IF EXISTS ai_tool_calls_occurred_at_idx;
DROP INDEX IF EXISTS ai_tool_calls_tool_name_idx;
DROP INDEX IF EXISTS ai_tool_calls_tenant_investigation_idx;
DROP TABLE IF EXISTS ai_tool_calls;
