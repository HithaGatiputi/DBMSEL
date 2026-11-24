"""RAG over the in-database knowledge base (MITRE ATT&CK summaries, NIST IR
guidance, organisational policy) using PostgreSQL full-text search."""
from __future__ import annotations

from . import db


def retrieve(categories: list[str], text: str = "", k: int = 5) -> list[dict]:
    return db.query(
        """SELECT doc_id, source, ref_id, title, body,
                  (categories && %s::text[])::int * 2
                  + COALESCE(ts_rank(tsv, websearch_to_tsquery('english', NULLIF(%s,''))), 0) AS score
             FROM kb_documents
            WHERE categories && %s::text[]
               OR (%s <> '' AND tsv @@ websearch_to_tsquery('english', %s))
            ORDER BY score DESC, doc_id LIMIT %s""",
        (categories, text, categories, text, text, k))
