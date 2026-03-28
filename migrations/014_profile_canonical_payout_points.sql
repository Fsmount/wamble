ALTER TABLE payouts
  ADD COLUMN IF NOT EXISTS points_canonical DECIMAL(10, 4);

UPDATE payouts
SET points_canonical = points_awarded
WHERE points_canonical IS NULL;

ALTER TABLE payouts
  ALTER COLUMN points_canonical SET NOT NULL;
