-- Use only this advisory's authoritative scores, with the same ordering and rounding as ingestion.
-- A scalar subquery with no rows clears all three fields when the advisory no longer has scores.
UPDATE vulnerability v
SET (base_score, base_severity, base_type) = (
    SELECT round(avs.score::numeric, 1), avs.severity, avs.type
    FROM advisory_vulnerability_score avs
    WHERE avs.advisory_id = $1 AND avs.vulnerability_id = v.id
    ORDER BY avs.type DESC, avs.score DESC
    LIMIT 1
)
FROM advisory_vulnerability av
WHERE av.advisory_id = $1
  AND v.id = av.vulnerability_id
  AND v.authoritative_advisory_id = av.advisory_id;
