-- 0014: evidence_refs on the action projection (10 §3 G1).
--
-- ActionRequested has always carried evidence_refs in the EVENT (the layer that
-- cannot lie); this surfaces it on action_current so the actions API — and the
-- eval harness's G1 grader ("every request_action carries >=1 evidence_refs") —
-- can read it without walking the event log. Rows projected before this column
-- read NULL; a Reset+replay backfills them from the events.
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS evidence_refs JSONB;
