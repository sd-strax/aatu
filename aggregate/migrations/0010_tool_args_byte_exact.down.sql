ALTER TABLE ai_tool_calls ALTER COLUMN tool_args TYPE JSONB USING tool_args::jsonb;
