-- 1. Enable required extensions
DO $$ BEGIN
    CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;
EXCEPTION WHEN OTHERS THEN
    CREATE EXTENSION IF NOT EXISTS vector;
END $$;

DO $$ BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;
EXCEPTION WHEN OTHERS THEN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
END $$;

-- 2. Create Enums for strict taxonomy enforcement
DO $$ BEGIN
    CREATE TYPE knowledge_domain AS ENUM (
        'engineering_rd',
        'work_career',
        'personal_os_code',
        'fitness_health',
        'systems_projects',
        'career_finance',
        'personal_life',
        'general_tech'
    );
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE knowledge_intent AS ENUM (
        'architecture_design',
        'debugging_troubleshooting',
        'academic_study',
        'workflow_automation',
        'decision_making',
        'personal_reflection',
        'reference_knowledge'
    );
EXCEPTION WHEN duplicate_object THEN null;
END $$;

-- Helper immutable function for array_to_string inside GENERATED column
CREATE OR REPLACE FUNCTION public.immutable_array_to_string(arr TEXT[], sep TEXT)
RETURNS TEXT LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT array_to_string(arr, sep);
$$;

-- 3. Core Knowledge Cards Table
CREATE TABLE IF NOT EXISTS public.knowledge_cards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    thread_hash TEXT NOT NULL UNIQUE,
    source_file TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ NOT NULL,
    turn_count INTEGER NOT NULL DEFAULT 1,

    -- Distilled Structured Fields
    title TEXT NOT NULL,
    distilled_summary TEXT NOT NULL,
    domain knowledge_domain NOT NULL,
    intent_type knowledge_intent NOT NULL,
    value_score SMALLINT NOT NULL CHECK (value_score >= 6 AND value_score <= 10),
    entities TEXT[] NOT NULL DEFAULT '{}',
    actionable_takeaways TEXT[] NOT NULL DEFAULT '{}',

    -- Raw Conversation Backup
    raw_turns JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Vector Embedding (halfvec saves 50% memory in HNSW index)
    embedding halfvec(768) NOT NULL,

    -- Generated Full-Text Search Vector (Multilingual 'simple' configuration)
    fts tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(distilled_summary, '')), 'B') ||
        setweight(to_tsvector('simple', immutable_array_to_string(entities, ' ')), 'A')
    ) STORED,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. High-Performance Indexes
CREATE INDEX IF NOT EXISTS idx_knowledge_cards_embedding_hnsw
    ON public.knowledge_cards
    USING hnsw (embedding halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS idx_knowledge_cards_fts
    ON public.knowledge_cards
    USING gin (fts);

CREATE INDEX IF NOT EXISTS idx_knowledge_cards_entities
    ON public.knowledge_cards
    USING gin (entities);

CREATE INDEX IF NOT EXISTS idx_knowledge_cards_domain_started
    ON public.knowledge_cards (domain, started_at DESC);

-- 5. Hybrid RAG Retrieval RPC with Reciprocal Rank Fusion (RRF)
CREATE OR REPLACE FUNCTION public.match_knowledge_hybrid(
    query_text TEXT,
    query_embedding halfvec(768),
    match_count INT DEFAULT 10,
    filter_domain knowledge_domain DEFAULT NULL,
    filter_min_score INT DEFAULT 6,
    full_text_weight FLOAT DEFAULT 1.0,
    semantic_weight FLOAT DEFAULT 1.5,
    rrf_k INT DEFAULT 50
)
RETURNS TABLE (
    id UUID,
    title TEXT,
    distilled_summary TEXT,
    domain knowledge_domain,
    intent_type knowledge_intent,
    entities TEXT[],
    actionable_takeaways TEXT[],
    started_at TIMESTAMPTZ,
    raw_turns JSONB,
    rrf_score FLOAT
)
LANGUAGE sql STABLE AS $$
WITH full_text AS (
    SELECT
        kc.id,
        ROW_NUMBER() OVER (
            ORDER BY ts_rank_cd(
                kc.fts,
                COALESCE(
                    NULLIF(websearch_to_tsquery('simple', query_text), ''::tsquery),
                    plainto_tsquery('simple', query_text)
                )
            ) DESC
        ) AS rank_ix
    FROM public.knowledge_cards kc
    WHERE (
        kc.fts @@ websearch_to_tsquery('simple', query_text)
        OR kc.fts @@ plainto_tsquery('simple', query_text)
        OR (
            query_text ~ '\w+' AND
            kc.fts @@ to_tsquery('simple', regexp_replace(trim(regexp_replace(query_text, '[^\w\s]', ' ', 'g')), '\s+', ' | ', 'g'))
        )
    )
      AND (filter_domain IS NULL OR kc.domain = filter_domain)
      AND kc.value_score >= filter_min_score
    LIMIT match_count * 2
),
semantic AS (
    SELECT
        kc.id,
        ROW_NUMBER() OVER (
            ORDER BY kc.embedding <=> query_embedding
        ) AS rank_ix
    FROM public.knowledge_cards kc
    WHERE (filter_domain IS NULL OR kc.domain = filter_domain)
      AND kc.value_score >= filter_min_score
    ORDER BY kc.embedding <=> query_embedding
    LIMIT match_count * 2
)
SELECT
    kc.id,
    kc.title,
    kc.distilled_summary,
    kc.domain,
    kc.intent_type,
    kc.entities,
    kc.actionable_takeaways,
    kc.started_at,
    kc.raw_turns,
    (
        COALESCE(1.0 / (rrf_k + full_text.rank_ix), 0.0) * full_text_weight +
        COALESCE(1.0 / (rrf_k + semantic.rank_ix), 0.0) * semantic_weight
    )::FLOAT AS rrf_score
FROM full_text
FULL OUTER JOIN semantic ON full_text.id = semantic.id
JOIN public.knowledge_cards kc ON COALESCE(full_text.id, semantic.id) = kc.id
ORDER BY rrf_score DESC
LIMIT match_count;
$$;
