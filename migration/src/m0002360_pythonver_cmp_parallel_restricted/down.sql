CREATE OR REPLACE FUNCTION public.pythonver_cmp(left_p text, right_p text) RETURNS integer
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $$
DECLARE
left_parts text[];
    right_parts text[];

    left_major BIGINT;
    left_minor BIGINT;
    left_patch BIGINT;

    right_major BIGINT;
    right_minor BIGINT;
    right_patch BIGINT;

    -- Pre-release, Post-release, Dev-release
    left_pre TEXT := NULL;
    right_pre TEXT := NULL;

    left_pre_num BIGINT := NULL;
    right_pre_num BIGINT := NULL;

    left_post BIGINT := NULL;
    right_post BIGINT := NULL;

    left_dev BIGINT := NULL;
    right_dev BIGINT := NULL;

    left_local TEXT := NULL;
    right_local TEXT := NULL;
BEGIN
    left_parts = regexp_split_to_array(substring(left_p, E'^[^[:alpha:]\\+-]+'), E'\\.');
    left_major = left_parts[1]::bigint;
    left_minor = coalesce(left_parts[2]::bigint, 0);
    left_patch = coalesce(left_parts[3]::bigint, 0);

    right_parts = regexp_split_to_array(substring(right_p, E'^[^[:alpha:]\\+-]+'), E'\\.');
    right_major = right_parts[1]::bigint;
    right_minor = coalesce(right_parts[2]::bigint, 0);
    right_patch = coalesce(right_parts[3]::bigint, 0);


IF left_major > right_major THEN RETURN +1;
    ELSIF left_major < right_major THEN RETURN -1;
END IF;

    IF left_minor > right_minor THEN RETURN +1;
    ELSIF left_minor < right_minor THEN RETURN -1;
END IF;

    IF left_patch > right_patch THEN RETURN +1;
    ELSIF left_patch < right_patch THEN RETURN -1;
END IF;

    -- Extract pre-release versions (allow `a1`, `b2`, `rc3` without hyphen)
    left_pre := (regexp_match(left_p, '\d[-_\.]?(a|b|rc)(\d*)'))[1];
    left_pre_num := NULLIF((regexp_match(left_p, '\d*[-_\.]?(a|b|rc)(\d*)'))[2], '')::BIGINT;

    right_pre := (regexp_match(right_p, '\d[-_\.]?(a|b|rc)(\d*)'))[1];
    right_pre_num := NULLIF((regexp_match(right_p, '\d*[-_\.]?(a|b|rc)(\d*)'))[2], '')::BIGINT;

    IF left_pre IS NOT NULL AND right_pre IS NULL THEN RETURN -1; END IF;
    IF right_pre IS NOT NULL AND left_pre IS NULL THEN RETURN +1; END IF;

    -- Compare pre-release versions (alpha < beta < rc)
    IF left_pre IS NOT NULL AND right_pre IS NOT NULL THEN
        IF left_pre < right_pre THEN RETURN -1;
        ELSIF left_pre > right_pre THEN RETURN +1;
        ELSIF left_pre_num < right_pre_num THEN RETURN -1;
        ELSIF left_pre_num > right_pre_num THEN RETURN +1;
END IF;
END IF;

    -- Extract post-release versions (postN)
    left_post := NULLIF((regexp_match(left_p, 'post(\d+)'))[1], '')::BIGINT;
    right_post := NULLIF((regexp_match(right_p, 'post(\d+)'))[1], '')::BIGINT;

    IF left_post IS NOT NULL AND right_post IS NULL THEN RETURN +1; END IF;
    IF right_post IS NOT NULL AND left_post IS NULL THEN RETURN -1; END IF;
    IF left_post IS NOT NULL AND right_post IS NOT NULL THEN
        IF left_post > right_post THEN RETURN +1;
        ELSIF left_post < right_post THEN RETURN -1;
END IF;
END IF;

    -- Extract dev-release versions (devN)
    left_dev := NULLIF((regexp_match(left_p, 'dev(\d+)'))[1], '')::BIGINT;
    right_dev := NULLIF((regexp_match(right_p, 'dev(\d+)'))[1], '')::BIGINT;

    IF left_dev IS NOT NULL AND right_dev IS NULL THEN RETURN -1; END IF;
    IF right_dev IS NOT NULL AND left_dev IS NULL THEN RETURN +1; END IF;
    IF left_dev IS NOT NULL AND right_dev IS NOT NULL THEN
        IF left_dev > right_dev THEN RETURN +1;
        ELSIF left_dev < right_dev THEN RETURN -1;
END IF;
END IF;

    -- Extract local-release versions (+string)
    left_local := (regexp_match(left_p, E'\\+([a-zA-Z0-9\\.]+)'))[1];
    right_local := (regexp_match(right_p, E'\\+([a-zA-Z0-9\\.]+)'))[1];

    IF left_local IS NOT NULL AND right_local IS NULL THEN RETURN +1; END IF;
    IF right_local IS NOT NULL AND left_local IS NULL THEN RETURN -1; END IF;
    IF left_local IS NOT NULL AND right_local IS NOT NULL THEN
        IF left_local > right_local THEN RETURN +1;
        ELSIF left_local < right_local THEN RETURN -1;
END IF;
END IF;


    -- If everything is equal, return 0
RETURN 0;

EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END
$$;
