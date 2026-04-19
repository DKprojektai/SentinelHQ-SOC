"""
SentinelHQ — Universal LLM Client
Supports any OpenAI-compatible API:
  - OpenRouter (cloud, many models)
  - LM Studio  (local)
  - Ollama     (local)
  - Together AI, Groq, Mistral, etc.
"""

import os
import logging
from typing import Optional

import requests

log = logging.getLogger(__name__)

LLM_API_URL = os.environ.get("LLM_API_URL", "https://openrouter.ai/api/v1").rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL   = os.environ.get("LLM_MODEL", "google/gemini-2.5-flash")


def call_multi(system: str, messages: list[dict], model: str = None,
               max_tokens: int = 1200) -> tuple[str, int]:
    """
    Multi-turn conversation call.
    messages: [{"role": "user"|"assistant", "content": "..."}]
    """
    model = model or LLM_MODEL
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    if "openrouter.ai" in LLM_API_URL:
        headers["HTTP-Referer"] = "https://sentinelhq.local"
        headers["X-Title"]      = "SentinelHQ"

    body = {
        "model":      model,
        "max_tokens": max_tokens,
        "messages":   [{"role": "system", "content": system}] + messages,
    }
    r = requests.post(f"{LLM_API_URL}/chat/completions",
                      headers=headers, json=body, timeout=60)
    r.raise_for_status()
    data   = r.json()
    text   = data["choices"][0]["message"]["content"]
    tokens = data.get("usage", {}).get("total_tokens", 0)
    return text, tokens


def call(system: str, user: str, model: str = None,
         max_tokens: int = 800) -> tuple[str, int]:
    """
    Call LLM and return (response_text, tokens_used).
    Works with any OpenAI-compatible /v1/chat/completions endpoint.
    """
    model = model or LLM_MODEL

    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"

    # OpenRouter-specific headers (ignored by other providers)
    if "openrouter.ai" in LLM_API_URL:
        headers["HTTP-Referer"] = "https://sentinelhq.local"
        headers["X-Title"]      = "SentinelHQ"

    body = {
        "model":      model,
        "max_tokens": max_tokens,
        "messages":   [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }

    url = f"{LLM_API_URL}/chat/completions"
    log.debug("LLM call → %s [%s]", url, model)

    r = requests.post(url, headers=headers, json=body, timeout=60)
    r.raise_for_status()

    data   = r.json()
    text   = data["choices"][0]["message"]["content"]
    tokens = data.get("usage", {}).get("total_tokens", 0)

    log.debug("LLM response: %d tokens", tokens)
    return text, tokens


def call_with_tools(system: str, messages: list[dict], tools: list[dict],
                    max_tokens: int = 1200) -> dict:
    """
    Call LLM with tool definitions (OpenAI function calling).
    Returns:
      {"type": "text",       "content": str,        "tokens": int}
      {"type": "tool_calls", "tool_calls": list,
                             "message":    dict,     "tokens": int}
    Raises on HTTP error so caller can fallback.
    """
    model = LLM_MODEL
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    if "openrouter.ai" in LLM_API_URL:
        headers["HTTP-Referer"] = "https://sentinelhq.local"
        headers["X-Title"]      = "SentinelHQ"

    body = {
        "model":       model,
        "max_tokens":  max_tokens,
        "messages":    [{"role": "system", "content": system}] + messages,
        "tools":       tools,
        "tool_choice": "auto",
    }

    r = requests.post(f"{LLM_API_URL}/chat/completions",
                      headers=headers, json=body, timeout=90)
    r.raise_for_status()

    data    = r.json()
    choice  = data["choices"][0]
    message = choice["message"]
    tokens  = data.get("usage", {}).get("total_tokens", 0)
    finish  = choice.get("finish_reason", "stop")

    if finish == "tool_calls" or message.get("tool_calls"):
        return {
            "type":       "tool_calls",
            "tool_calls": message["tool_calls"],
            "message":    message,
            "tokens":     tokens,
        }

    return {
        "type":    "text",
        "content": message.get("content") or "",
        "tokens":  tokens,
    }


def ping() -> tuple[bool, str]:
    """Test if LLM API is reachable. Returns (ok, message)."""
    try:
        # Try /models endpoint first (most providers support it)
        headers = {"Content-Type": "application/json"}
        if LLM_API_KEY:
            headers["Authorization"] = f"Bearer {LLM_API_KEY}"

        r = requests.get(f"{LLM_API_URL}/models",
                         headers=headers, timeout=10)
        if r.ok:
            return True, f"OK ({LLM_API_URL})"

        # Fallback: try a minimal completion
        text, _ = call("You are helpful.", "Say: OK", max_tokens=5)
        return True, f"OK via completion ({LLM_API_URL})"

    except requests.exceptions.ConnectionError:
        return False, f"Nepavyko prisijungti prie {LLM_API_URL}"
    except requests.exceptions.Timeout:
        return False, f"Timeout ({LLM_API_URL})"
    except Exception as e:
        return False, str(e)
