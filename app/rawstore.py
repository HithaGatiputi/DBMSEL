"""Raw / semi-structured log store.

Primary backend: MongoDB (schema-less documents, full-text index).
Fallback: PostgreSQL JSONB table `raw_logs_fallback` when MongoDB is down.
SECURITY_EVENTS.raw_log_ref holds the document id in either backend.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from . import config, db


class RawStore:
    def __init__(self) -> None:
        self.backend = "postgres-jsonb"
        self._col = None
        try:
            import pymongo
            client = pymongo.MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=1500)
            client.admin.command("ping")
            self._col = client[config.MONGO_DB]["raw_logs"]
            self._col.create_index([("$**", "text")], name="fulltext")
            self._col.create_index("sql_event_id")
            self.backend = "mongodb"
        except Exception:
            self._col = None

    # ------------------------------------------------------------------
    def put_many(self, docs: list[dict]) -> list[str]:
        if not docs:
            return []
        if self._col is not None:
            res = self._col.insert_many([dict(d) for d in docs])
            return [str(i) for i in res.inserted_ids]
        refs = [uuid.uuid4().hex for _ in docs]
        with db.conn() as c, c.cursor() as cur:
            cur.executemany(
                "INSERT INTO raw_logs_fallback (raw_log_ref, payload) VALUES (%s, %s::jsonb)",
                [(r, json.dumps(d, default=str)) for r, d in zip(refs, docs)])
            c.commit()
        return refs

    def link(self, refs: list[str], event_ids: list[int]) -> None:
        """Back-reference the SQL event id into each raw document."""
        if self._col is not None:
            from bson import ObjectId
            from pymongo import UpdateOne
            ops = [UpdateOne({"_id": ObjectId(r)}, {"$set": {"sql_event_id": int(e)}})
                   for r, e in zip(refs, event_ids)]
            if ops:
                self._col.bulk_write(ops, ordered=False)
        else:
            with db.conn() as c, c.cursor() as cur:
                cur.executemany(
                    "UPDATE raw_logs_fallback SET payload = payload || %s::jsonb WHERE raw_log_ref = %s",
                    [(json.dumps({"sql_event_id": int(e)}), r) for r, e in zip(refs, event_ids)])
                c.commit()

    def get(self, ref: str) -> dict | None:
        if self._col is not None:
            from bson import ObjectId
            try:
                d = self._col.find_one({"_id": ObjectId(ref)})
            except Exception:
                return None
            if d:
                d["_id"] = str(d["_id"])
            return d
        row = db.one("SELECT raw_log_ref, payload FROM raw_logs_fallback WHERE raw_log_ref=%s", (ref,))
        return {"_id": row["raw_log_ref"], **row["payload"]} if row else None

    def verify(self, ref: str, expected: str | None) -> str:
        """'verified' | 'TAMPERED' | 'missing' | 'no-hash'"""
        if not expected:
            return "no-hash"
        doc = self.get(ref)
        if doc is None:
            return "missing"
        from .ingest import doc_sha256
        return "verified" if doc_sha256(doc) == expected else "TAMPERED"

    def search(self, text: str, limit: int = 25) -> list[dict]:
        if self._col is not None:
            cur = (self._col.find({"$text": {"$search": text}},
                                  {"score": {"$meta": "textScore"}})
                   .sort([("score", {"$meta": "textScore"})]).limit(limit))
            out = []
            for d in cur:
                d["_id"] = str(d["_id"])
                out.append(d)
            return out
        rows = db.query(
            "SELECT raw_log_ref, payload FROM raw_logs_fallback "
            "WHERE payload::text ILIKE %s LIMIT %s", (f"%{text}%", limit))
        return [{"_id": r["raw_log_ref"], **r["payload"]} for r in rows]

    def count(self) -> int:
        if self._col is not None:
            return self._col.estimated_document_count()
        return db.one("SELECT COUNT(*) AS n FROM raw_logs_fallback")["n"]

    def clear(self) -> None:
        if self._col is not None:
            self._col.delete_many({})
        else:
            db.query("DELETE FROM raw_logs_fallback")


_store: RawStore | None = None


def store() -> RawStore:
    global _store
    if _store is None:
        _store = RawStore()
    return _store
