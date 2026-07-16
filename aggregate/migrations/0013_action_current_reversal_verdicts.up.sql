-- 0013_action_current_reversal_verdicts: Position C back-references (04 §7.1).
--
-- reversibility freezes the action type's classification (reversible |
-- best_effort | irreversible) at request time, so the REVERSED-claim gate reads
-- the value the analyst approved under — a later catalog edit cannot
-- re-classify an in-flight action. NULL for actions requested before the field
-- existed (readers fall back to the live catalog).
--
-- reversed_by_ref / reversal_attempted_by_ref make a reversal queryable from
-- the ORIGINAL action's side, not just via the reversing action's forward
-- reversal_of_ref:
--   reversed_by_ref            accompanies status REVERSED — the verified undo.
--   reversal_attempted_by_ref  records a fully-successful but UNVERIFIED
--                              reversing dispatch (action.reversal_attempted);
--                              the original honestly stays SUCCEEDED.
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS reversibility TEXT;
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS reversed_by_ref UUID;
ALTER TABLE action_current ADD COLUMN IF NOT EXISTS reversal_attempted_by_ref UUID;
