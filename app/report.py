"""Structured incident report (JSON + Markdown)."""
from __future__ import annotations

from datetime import datetime, timezone

from . import investigate as inv


def build(iid: int) -> dict | None:
    a = inv.investigate(iid)
    if not a:
        return None
    tl = inv.get_timeline(iid)
    i = a["incident"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "incident_id": iid, "title": i["title"], "severity": i["severity_level"], "status": i["status"],
        "risk_score": float(i["risk_score"]), "analyst": i["analyst"],
        "executive_summary": a["explanation"], "summary_source": a["explanation_source"],
        "timeline": [{"step": r["step_sequence"], "time": r["event_timestamp"].isoformat(timespec="seconds"),
                      "category": r["event_category"], "user": r["username"], "host": r["hostname"],
                      "source_ip": r["source_ip"], "risk": float(r["risk_score"]), "detail": r["detail"],
                      "event_id": r["event_id"]} for r in tl],
        "affected": {"users": [u["username"] for u in a["entities"]["users"]],
                     "devices": [d["hostname"] for d in a["entities"]["devices"]],
                     "ip_addresses": a["entities"]["ips"]},
        "findings": a["patterns"], "kill_chain": a["kill_chain"],
        "risk_breakdown": [{"component": r["component"], "contribution": float(r["contribution"]),
                            "rule": r["weight"]} for r in a["risk_breakdown"]],
        "framework_context": a["context"],
        "containment": [{"type": b["entity_type"], "entity": b["entity"], "by": "automatic" if b["actor"] == "auto-response" else b["blocked_by"],
                         "since": b["created_at"].isoformat(timespec="seconds"), "active": b["active"],
                         "blocked_attempts": b["blocked_attempts"], "reason": b["reason"]} for b in inv.get_blocks(iid)],
        "investigation_actions": [{"time": a["performed_at"].isoformat(timespec="seconds"), "type": a["action_type"],
                                   "notes": a["action_notes"], "analyst": a["analyst"]} for a in inv.get_actions(iid)],
        "involved": {"user": i.get("primary_user"), "user_role": i.get("user_entity_role"),
                     "device": i.get("primary_device"), "device_role": i.get("device_entity_role")},
        "audit_trail": [{"time": x["changed_at"].isoformat(timespec="seconds"), "field": x["field_changed"],
                         "old": x["old_value"], "new": x["new_value"], "by": x["analyst"] or x["actor"]}
                        for x in inv.get_audit(iid) if x["field_changed"] != "evidence_added"],
    }


def to_markdown(r: dict) -> str:
    L = [f"# Incident Report #{r['incident_id']}: {r['title']}", "",
         f"**Severity:** {r['severity']}  |  **Risk:** {r['risk_score']}/100  |  **Status:** {r['status']}  |  "
         f"**Analyst:** {r['analyst'] or 'unassigned'}", f"*Generated {r['generated_at']}*", "",
         "## Executive summary", r["executive_summary"], "", "## Affected entities",
         f"- Primary user: {r['involved']['user'] or 'n/a'} ({r['involved']['user_role'] or '-'}); "
         f"primary device: {r['involved']['device'] or 'n/a'} ({r['involved']['device_role'] or '-'})",
         f"- Users: {', '.join(r['affected']['users']) or 'n/a'}",
         f"- Devices: {', '.join(r['affected']['devices'])}",
         f"- IP addresses: {', '.join(r['affected']['ip_addresses'])}", "", "## Timeline",
         "| # | Time (UTC) | Category | User | Host | Source IP | Risk |", "|---|---|---|---|---|---|---|"]
    for t in r["timeline"]:
        L.append(f"| {t['step']} | {t['time']} | {t['category']} | {t['user'] or '-'} | {t['host']} | {t['source_ip'] or '-'} | {t['risk']} |")
    L += ["", "## Findings"] + [f"- **{f['pattern']}** ({f['mitre']}): {f['summary']}" for f in r["findings"]]
    L += ["", "## Risk score breakdown"] + [f"- {b['component']}: {b['contribution']} ({b['rule']})" for b in r["risk_breakdown"]]
    L += ["", "## Framework context"] + [f"- **{c['source']} {c['ref']} – {c['title']}**: {c['text']}" for c in r["framework_context"]]
    L += ["", "## Containment"] + ([f"- {'Active' if c['active'] else 'Lifted'}: {c['type']} **{c['entity']}** blocked by {c['by']} "
                                     f"since {c['since']}; {c['blocked_attempts']} blocked attempt(s) since. Reason: {c['reason']}"
                                     for c in r["containment"]] or ["- none"])
    L += ["", "## Investigation actions"] + [f"- {a['time']} **{a['type']}** by {a['analyst']}: {a['notes']}"
                                             for a in r["investigation_actions"]] or ["- none"]
    L += ["", "## Audit trail"] + [f"- {a['time']} {a['field']}: {a['old']} -> {a['new']} by {a['by']}" for a in r["audit_trail"]]
    return "\n".join(L)
