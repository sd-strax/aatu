-- 0020: record why a FAILED action failed. ActionResulted now carries the
-- adapter/dispatch error reason (08 §6c); materialize it so the actions API and
-- the workbench ledger can show the analyst the reason instead of a bare FAILED.
-- Empty for successes and for actions resulted before this column existed.
ALTER TABLE action_current ADD COLUMN error_detail TEXT NOT NULL DEFAULT '';
