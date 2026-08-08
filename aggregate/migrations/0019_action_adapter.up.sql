-- 0019: record which adapter dispatched an x-action, so a surface can show the
-- analyst which tool actually acted (provenance for trust + audit). The value is
-- already in the event log (action.dispatched → ActionDispatched.Adapter); this
-- materializes it onto the projection so the actions API can serve it without
-- walking events. Empty until the action is dispatched (a still-pending action
-- has no dispatcher yet).
ALTER TABLE action_current ADD COLUMN adapter TEXT NOT NULL DEFAULT '';
