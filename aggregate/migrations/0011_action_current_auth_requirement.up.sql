-- 0011_action_current_auth_requirement: surface the frozen Gate 2 authorization
-- requirement on the action projection so the approval surface (Phase D) can
-- render and enforce it without re-evaluating policy.
--
-- required_mode is the authorization mode Gate 2 resolved at request time
-- (MANUAL / TWO_PARTY / AUTO_POLICY); TWO_PARTY means a solo approval is
-- illegal. secondary_approver_pool bounds who may complete a two-party
-- approval. reversal_of_ref lets a manually-approved reversal start the
-- ReversalSaga (the original it reverses is otherwise only in the event
-- payload). All are frozen at request time and never change.
-- parameters is the frozen action parameters (the write adapter needs them at
-- dispatch, and the approver needs to see them). Frozen at request time.
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS required_mode TEXT;
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS secondary_approver_pool JSONB;
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS reversal_of_ref UUID;
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS parameters JSONB;
