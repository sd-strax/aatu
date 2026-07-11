ALTER TABLE action_current DROP COLUMN IF EXISTS primary_approved_at;
ALTER TABLE action_current DROP COLUMN IF EXISTS parameters;
ALTER TABLE action_current DROP COLUMN IF EXISTS reversal_of_ref;
ALTER TABLE action_current DROP COLUMN IF EXISTS secondary_approver_pool;
ALTER TABLE action_current DROP COLUMN IF EXISTS required_mode;
