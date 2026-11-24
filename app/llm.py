"""LLM access with three interchangeable providers.

  anthropic  Claude via the Anthropic API (needs ANTHROPIC_API_KEY, paid)
  gemini     Google Gemini API (free key from Google AI Studio; needs internet)
  ollama     free, local, offline: a model served by Ollama on this machine
             (no account, no key, the security data never leaves the laptop)
  none       no LLM: deterministic offline intent library + rule-based text

LLM_PROVIDER=auto (default) picks the first one available in that order. Every call returns None
on any failure, so callers always fall back to the offline path.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from . import config

_client = None
_ollama_ok: tuple[float, bool] = (0.0, False)


def _ollama_ready() -> bool:
    """Server reachable and model pulled (cached for 30 s)."""
    global _ollama_ok
    if time.time() - _ollama_ok[0] < 30:
        return _ollama_ok[1]
    ok = False
    try:
        with urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=2) as r:
            names = {m["name"] for m in json.load(r).get("models", [])}
        ok = config.OLLAMA_MODEL in names or f"{config.OLLAMA_MODEL}:latest" in names
    except Exception:
        ok = False
    _ollama_ok = (time.time(), ok)
    return ok


def provider() -> str:
    p = config.LLM_PROVIDER
    if p == "auto":
        if config.ANTHROPIC_API_KEY:
            return "anthropic"
        if config.GEMINI_API_KEY:
            return "gemini"
        return "ollama" if _ollama_ready() else "none"
    if p == "anthropic":
        return "anthropic" if config.ANTHROPIC_API_KEY else "none"
    if p == "gemini":
        return "gemini" if config.GEMINI_API_KEY else "none"
    if p == "ollama":
        return "ollama" if _ollama_ready() else "none"
    return "none"


def available() -> bool:
    return provider() != "none"


def describe() -> str:
    p = provider()
    return {"anthropic": f"anthropic ({config.LLM_MODEL})", "gemini": f"gemini ({config.GEMINI_MODEL})",
            "ollama": f"ollama, local ({config.OLLAMA_MODEL})"}.get(p, "offline (rule-based)")


def _ollama(system: str, user: str, max_tokens: int) -> str | None:
    body = json.dumps({"model": config.OLLAMA_MODEL, "stream": False,
                       "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                       "keep_alive": "30m",                      # stay loaded between questions
                       "options": {"temperature": 0, "num_predict": min(max_tokens, 400), "num_ctx": 8192}}).encode()
    req = urllib.request.Request(config.OLLAMA_URL + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=config.OLLAMA_TIMEOUT) as r:
        return json.load(r)["message"]["content"].strip()


def _gemini(system: str, user: str, max_tokens: int) -> str | None:
    """Gemini REST API. The key travels in a header, never in the URL."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.GEMINI_MODEL}:generateContent"
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        # thinking models spend part of the budget on reasoning, so allow headroom
        "generationConfig": {"temperature": 0, "maxOutputTokens": max(max_tokens, 2048)},
    }).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "x-goog-api-key": config.GEMINI_API_KEY})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.load(r)
    parts = data["candidates"][0]["content"].get("parts", [])
    return "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()


def last_error() -> str | None:
    return _last_error


_last_error: str | None = None


# Models that accept server-side refusal fallbacks (fallbacks="default").
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2", "claude-fable-5-1", "claude-opus-5"}


def _anthropic(system: str, user: str, max_tokens: int) -> str | None:
    """Claude via the official SDK. Current models think before answering, so
    max_tokens gets generous headroom (thinking counts against it) and effort
    is 'low': these are short, well-specified tasks (SQL, a 150-word summary).
    Security wording can trip a safety classifier, so refusals fall back to
    another model server-side; a final refusal returns None (offline path)."""
    global _client
    if _client is None:
        import anthropic
        _client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    kwargs = dict(model=config.LLM_MODEL, max_tokens=max(max_tokens, 8000), system=system,
                  output_config={"effort": "low"}, messages=[{"role": "user", "content": user}])
    if config.LLM_MODEL in _FALLBACK_MODELS:
        msg = _client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
    else:
        msg = _client.messages.create(**kwargs)
    if msg.stop_reason == "refusal":
        return None
    return "".join(b.text for b in msg.content if b.type == "text").strip()


def chain() -> list[str]:
    """Providers to try, in order. In auto mode a cloud failure (no internet,
    quota) falls through to the local Ollama model before giving up."""
    if config.LLM_PROVIDER != "auto":
        p = provider()
        return [] if p == "none" else [p]
    out = []
    if config.ANTHROPIC_API_KEY:
        out.append("anthropic")
    if config.GEMINI_API_KEY:
        out.append("gemini")
    if _ollama_ready():
        out.append("ollama")
    return out


_CALL = {"ollama": _ollama, "gemini": _gemini, "anthropic": _anthropic}
last_provider: str | None = None


def complete(system: str, user: str, max_tokens: int = 900) -> str | None:
    global _last_error, last_provider
    for p in chain():
        try:
            text = _CALL[p](system, user, max_tokens)
            if text:
                last_provider = p
                return text
        except urllib.error.HTTPError as e:        # e.g. bad key, quota, unknown model
            _last_error = f"{p} HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"
        except Exception as e:                      # e.g. no internet, timeout
            _last_error = f"{p}: {type(e).__name__}: {str(e)[:200]}"
    return None
