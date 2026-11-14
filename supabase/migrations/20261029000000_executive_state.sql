-- Migration: 20261029000000_executive_state.sql
-- Description: Cloud-Primary Hot State and OCC synchronization function

CREATE TABLE IF NOT EXISTS public.executive_state (
    state_key TEXT PRIMARY KEY CHECK (state_key IN (
        'current_priorities',
        'pillar_metrics',
        'decision_log',
        'agent_prompts_bundle'
    )),
    content TEXT NOT NULL,
    checksum TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_by TEXT NOT NULL CHECK (updated_by IN (
        'cli_agent',
        'fastmcp_tool',
        'github_action',
        'manual_sync'
    )),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.executive_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service Role Full Access on Executive State"
ON public.executive_state
FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.upsert_executive_state_occ(
    p_state_key TEXT,
    p_content TEXT,
    p_checksum TEXT,
    p_expected_version INTEGER,
    p_updated_by TEXT
) RETURNS TABLE(success BOOLEAN, new_version INTEGER, current_content TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_current_version INTEGER;
    v_current_content TEXT;
BEGIN
    SELECT version, content INTO v_current_version, v_current_content
    FROM public.executive_state
    WHERE state_key = p_state_key
    FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO public.executive_state (state_key, content, checksum, version, updated_by)
        VALUES (p_state_key, p_content, p_checksum, 1, p_updated_by);
        RETURN QUERY SELECT true, 1, p_content;
        RETURN;
    END IF;

    IF v_current_version <> p_expected_version THEN
        RETURN QUERY SELECT false, v_current_version, v_current_content;
        RETURN;
    END IF;

    UPDATE public.executive_state
    SET content = p_content,
        checksum = p_checksum,
        version = v_current_version + 1,
        updated_by = p_updated_by,
        updated_at = now()
    WHERE state_key = p_state_key;

    RETURN QUERY SELECT true, v_current_version + 1, p_content;
END;
$$;
