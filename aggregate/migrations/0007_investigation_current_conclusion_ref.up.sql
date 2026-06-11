-- 0007_investigation_current_conclusion_ref: the ConclusionSlot reference on
-- the basic-state projection (01-domain-model.md §Extension 4).
--
-- NULL until the investigation is concluded; set to the Report id on
-- InvestigationConcluded, cleared back to NULL on InvestigationReopened.

ALTER TABLE investigation_current ADD COLUMN IF NOT EXISTS conclusion_ref TEXT;
