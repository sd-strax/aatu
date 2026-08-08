-- 0021: the operational reference a dispatch returned (e.g. the created
-- ServiceNow incident number) — the analyst's handle into the external system
-- of record, shown on the action ledger. From ActionResulted.raw_response_ref.
ALTER TABLE action_current ADD COLUMN raw_response_ref TEXT NOT NULL DEFAULT '';
