-- Bind each machine credential to the human whose eligibility is accountable for its use.
--
-- Existing rows with a surviving creator have an auditable provenance path, so they can be
-- migrated as verified. Rows whose creator was removed already have no trustworthy person to
-- charge or gate; they remain explicitly ambiguous until an operator recreates the token.

ALTER TABLE machine_tokens
    ADD COLUMN IF NOT EXISTS beneficiary_id TEXT REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE machine_tokens
    ADD COLUMN IF NOT EXISTS beneficiary_status TEXT NOT NULL DEFAULT 'ambiguous';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'machine_tokens'::regclass
          AND conname = 'machine_tokens_beneficiary_status'
    ) THEN
        ALTER TABLE machine_tokens
            ADD CONSTRAINT machine_tokens_beneficiary_status
            CHECK (beneficiary_status IN ('verified', 'ambiguous'));
    END IF;
END $$;

UPDATE machine_tokens
SET beneficiary_id = created_by,
    beneficiary_status = 'verified'
WHERE created_by IS NOT NULL
  AND beneficiary_id IS NULL;

CREATE INDEX IF NOT EXISTS machine_tokens_beneficiary_idx ON machine_tokens (beneficiary_id);
