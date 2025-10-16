-- Rollback the license expansion optimization
-- This restores the original UUID-based function signatures

-- Drop the optimized functions
DROP FUNCTION IF EXISTS expand_license_expression_with_mappings(TEXT, license_mapping[]);

-- Drop the composite type
DROP TYPE IF EXISTS license_mapping CASCADE;
