-- Migration: 20261102000000_user_facts.sql
-- Description: Evolving Fact Layer with Contradiction Resolution & History Archiving

CREATE TABLE IF NOT EXISTS public.user_facts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category TEXT NOT NULL CHECK (category IN (
        'finance',
        'career',
        'engineering_rd',
        'health',
        'preferences',
        'general'
    )),
    fact_key TEXT NOT NULL UNIQUE,
    fact_value JSONB NOT NULL,
    confidence NUMERIC(3, 2) DEFAULT 1.0,
    source_card_id UUID REFERENCES public.knowledge_cards(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    history JSONB[] DEFAULT ARRAY[]::JSONB[]
);

CREATE INDEX IF NOT EXISTS idx_user_facts_category ON public.user_facts(category);
CREATE INDEX IF NOT EXISTS idx_user_facts_key ON public.user_facts(fact_key);

ALTER TABLE public.user_facts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'user_facts' AND policyname = 'Service Role Full Access on User Facts'
    ) THEN
        CREATE POLICY "Service Role Full Access on User Facts"
        ON public.user_facts
        FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'user_facts' AND policyname = 'Allow Read Access on User Facts'
    ) THEN
        CREATE POLICY "Allow Read Access on User Facts"
        ON public.user_facts
        FOR SELECT
        TO anon, authenticated
        USING (true);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.upsert_user_fact(
    p_fact_key TEXT,
    p_fact_value JSONB,
    p_category TEXT DEFAULT 'general',
    p_confidence NUMERIC DEFAULT 1.0,
    p_source_card_id UUID DEFAULT NULL
) RETURNS TABLE(
    id UUID,
    fact_key TEXT,
    category TEXT,
    fact_value JSONB,
    confidence NUMERIC,
    updated_at TIMESTAMPTZ,
    history JSONB[],
    action TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_existing RECORD;
    v_history_entry JSONB;
    v_new_history JSONB[];
BEGIN
    SELECT * INTO v_existing
    FROM public.user_facts
    WHERE public.user_facts.fact_key = p_fact_key
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY
        INSERT INTO public.user_facts (category, fact_key, fact_value, confidence, source_card_id, updated_at, history)
        VALUES (p_category, p_fact_key, p_fact_value, p_confidence, p_source_card_id, now(), ARRAY[]::JSONB[])
        RETURNING public.user_facts.id, public.user_facts.fact_key, public.user_facts.category, public.user_facts.fact_value, public.user_facts.confidence, public.user_facts.updated_at, public.user_facts.history, 'INSERTED'::TEXT;
        RETURN;
    END IF;

    v_history_entry := jsonb_build_object(
        'fact_value', v_existing.fact_value,
        'category', v_existing.category,
        'confidence', v_existing.confidence,
        'source_card_id', v_existing.source_card_id,
        'updated_at', v_existing.updated_at,
        'archived_at', now()
    );

    v_new_history := array_append(COALESCE(v_existing.history, ARRAY[]::JSONB[]), v_history_entry);

    RETURN QUERY
    UPDATE public.user_facts
    SET fact_value = p_fact_value,
        category = COALESCE(p_category, v_existing.category),
        confidence = COALESCE(p_confidence, v_existing.confidence),
        source_card_id = COALESCE(p_source_card_id, v_existing.source_card_id),
        history = v_new_history,
        updated_at = now()
    WHERE public.user_facts.fact_key = p_fact_key
    RETURNING public.user_facts.id, public.user_facts.fact_key, public.user_facts.category, public.user_facts.fact_value, public.user_facts.confidence, public.user_facts.updated_at, public.user_facts.history, 'UPDATED'::TEXT;
END;
$$;
