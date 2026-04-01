CREATE TYPE cvss3_a AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss3_ac AS ENUM ('l', 'h');
CREATE TYPE cvss3_av AS ENUM ('n', 'a', 'l', 'p');
CREATE TYPE cvss3_c AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss3_i AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss3_pr AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss3_s AS ENUM ('u', 'c');
CREATE TYPE cvss3_severity AS ENUM ('none', 'low', 'medium', 'high', 'critical');
CREATE TYPE cvss3_ui AS ENUM ('n', 'r');
CREATE TYPE cvss4_ac AS ENUM ('l', 'h');
CREATE TYPE cvss4_at AS ENUM ('n', 'p');
CREATE TYPE cvss4_av AS ENUM ('n', 'a', 'l', 'p');
CREATE TYPE cvss4_pr AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss4_sa AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss4_sc AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss4_si AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss4_ui AS ENUM ('n', 'p', 'a');
CREATE TYPE cvss4_va AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss4_vc AS ENUM ('n', 'l', 'h');
CREATE TYPE cvss4_vi AS ENUM ('n', 'l', 'h');

CREATE FUNCTION public.cvss3_a_score(a_p public.cvss3_a) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if a_p = 'n'::cvss3_a then
        return 0.0;
    elsif a_p = 'l'::cvss3_a then
        return 0.22;
    elsif a_p = 'h'::cvss3_a then
        return 0.56;
    end if;

    return 0.85;

end;
$$;

CREATE FUNCTION public.cvss3_ac_score(ac_p public.cvss3_ac) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if ac_p = 'h'::cvss3_ac then
        return 0.44;
    elsif ac_p = 'l'::cvss3_ac then
        return 0.77;
    end if;

    return 0.0;

end;
$$;

CREATE FUNCTION public.cvss3_av_score(av_p public.cvss3_av) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if av_p = 'p'::cvss3_av then
        return 0.20;
    elsif av_p = 'l'::cvss3_av then
        return 0.55;
    elsif av_p = 'a'::cvss3_av then
        return 0.62;
    elsif av_p = 'n'::cvss3_av then
        return 0.85;
    end if;

    return 0.0;

end;
$$;

CREATE FUNCTION public.cvss3_c_score(c_p public.cvss3_c) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if c_p = 'n'::cvss3_c then
        return 0.0;
    elsif c_p = 'l'::cvss3_c then
        return 0.22;
    elsif c_p = 'h'::cvss3_c then
        return 0.56;
    end if;

    return 0.85;

end;
$$;

CREATE FUNCTION public.cvss3_scope_changed(s_p public.cvss3_s) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
begin
    return s_p = 'c'::cvss3_s;

end;
$$;

CREATE FUNCTION public.cvss3_ui_score(ui_p public.cvss3_ui) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if ui_p = 'r'::cvss3_ui then
        return 0.62;
    end if;

    return 0.85;

end;
$$;

CREATE FUNCTION public.cvss3_pr_scoped_score(pr_p public.cvss3_pr, scope_changed_p boolean) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if pr_p = 'h'::cvss3_pr then
        if scope_changed_p then
            return 0.50;
        else
            return 0.27;
        end if;
    elsif pr_p = 'l'::cvss3_pr then
        if scope_changed_p then
            return 0.68;
        else
            return 0.62;
        end if;
    end if;

    return 0.85;

end;
$$;

CREATE FUNCTION public.cvss3_i_score(i_p public.cvss3_i) RETURNS real
    LANGUAGE plpgsql
    AS $$
begin
    if i_p = 'n'::cvss3_i then
        return 0.0;
    elsif i_p = 'l'::cvss3_i then
        return 0.22;
    elsif i_p = 'h'::cvss3_i then
        return 0.56;
    end if;

    return 0.85;

end;
$$;

CREATE FUNCTION public.cvss3_impact(cvss3_p public.cvss3) RETURNS real
    LANGUAGE plpgsql
    AS $$
declare
    c_score decimal;
    i_score decimal;
    a_score decimal;
begin
    c_score := cvss3_c_score(cvss3_p.c);
    i_score := cvss3_i_score(cvss3_p.i);
    a_score := cvss3_a_score(cvss3_p.a);

    return (1.0 - abs((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score)));
end;
$$;

CREATE FUNCTION public.cvss3_exploitability(cvss3_p public.cvss3) RETURNS real
    LANGUAGE plpgsql
    AS $$
declare
    av_score decimal;
    ac_score decimal;
    ui_score decimal;
    pr_score decimal;
    scope_changed bool;
begin
    scope_changed = cvss3_scope_changed(cvss3_p.s);

    av_score := cvss3_av_score(cvss3_p.av);
    ac_score := cvss3_ac_score(cvss3_p.ac);
    ui_score := cvss3_ui_score(cvss3_p.ui);
    pr_score := cvss3_pr_scoped_score(cvss3_p.pr, scope_changed);

    return (8.22 * av_score * ac_score * pr_score * ui_score);
end;
$$;

CREATE FUNCTION public.cvss3_score(cvss3_p public.cvss3) RETURNS real
    LANGUAGE plpgsql
    AS $$
declare
    exploitability decimal;
    iss decimal;
    iss_scoped decimal;
    score decimal;
begin
    if cvss3_p is null then
        return null;
    end if;

    exploitability := cvss3_exploitability(cvss3_p);
    iss = cvss3_impact( cvss3_p );

    if not(cvss3_scope_changed( cvss3_p.s)) then
        iss_scoped := 6.42 * iss;
    else
        iss_scoped := (7.52 * (iss - 0.029)) - pow(3.25 * (iss - 0.02), 15.0);
    end if;

    if iss_scoped <= 0.0 then
        score := 0.0;
    elsif not(cvss3_scope_changed( cvss3_p.s)) then
        score := least(iss_scoped + exploitability, 10.0);
    else
        score := least(1.08 * (iss_scoped + exploitability), 10.0);
    end if;

    return score;
end
$$;

CREATE FUNCTION public.cvss3_severity(score_p double precision) RETURNS public.cvss3_severity
    LANGUAGE plpgsql
    AS $$
begin
    if score_p is null then
        return null;
    end if;

    if score_p <= 3.9 then
        return 'low'::"cvss3_severity";
    end if;

    if score_p <= 6.9 then
        return 'medium'::"cvss3_severity";
    end if;

    if score_p <= 8.9 then
        return 'high'::"cvss3_severity";
    end if;

    return 'critical'::"cvss3_severity";
end
$$;

ALTER TABLE vulnerability
    DROP CONSTRAINT IF EXISTS base_score_consistency,
    DROP COLUMN IF EXISTS base_type,
    ALTER COLUMN base_severity TYPE cvss3_severity USING base_severity::text::cvss3_severity;

CREATE INDEX cvss3_adv_id_idx ON cvss3 USING btree (advisory_id);
CREATE INDEX cvss3_vuln_id_idx ON cvss3 USING btree (vulnerability_id);
CREATE INDEX cvss3_adv_id_vuln_id_minor_version_idx ON cvss3 USING btree (advisory_id, vulnerability_id, minor_version);
CREATE INDEX cvss4_adv_id_idx ON cvss4 USING btree (advisory_id);
CREATE INDEX cvss4_vuln_id_idx ON cvss4 USING btree (vulnerability_id);
