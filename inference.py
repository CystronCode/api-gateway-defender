"""
Baseline Inference Script — API Gateway Defender
=================================================
Runs the heuristic agent on all 3 tasks and prints structured output
in the required [START]/[STEP]/[END] format for the OpenEnv validator.

Usage
-----
  python inference.py

  # With LLM proxy (injected by validator):
  API_BASE_URL=https://... API_KEY=... python inference.py

  # Against a different server:
  ENV_BASE_URL=https://... python inference.py
"""

import json
import os
import sys
import urllib.request
from typing import Any, Dict

# Use the LiteLLM proxy credentials injected by the validator.
# API_BASE_URL must end WITHOUT a trailing slash for /chat/completions appending.
API_KEY      = os.getenv("API_KEY", os.getenv("OPENAI_API_KEY", ""))
_raw_base    = os.getenv("API_BASE_URL", "").rstrip("/")
LLM_BASE_URL = _raw_base if _raw_base else "https://api.openai.com/v1"
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "https://cystroncode-api-gateway-defender.hf.space")
LLM_MODEL    = os.getenv("LLM_MODEL", "gpt-4o-mini")

TASK_IDS = ["easy", "medium", "hard"]


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _post(path: str, body: Any) -> Any:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{ENV_BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# ─── Heuristic agent ──────────────────────────────────────────────────────────

def _heuristic_action(task_id: str, obs: Dict[str, Any]) -> Dict[str, Any]:
    requests_list = obs.get("observation", obs).get("recent_requests", [])

    if task_id == "easy":
        ip_counts: Dict[str, int] = {}
        for req in requests_list:
            if req.get("path") == "/login" and req.get("method") == "POST":
                ip = req.get("ip", "")
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        suspect_ip = max(ip_counts, key=lambda k: ip_counts[k]) if ip_counts else "185.220.101.47"
        return {"action_type": "block_ip", "target_ip": suspect_ip}

    elif task_id == "medium":
        ua_counts: Dict[str, int] = {}
        for req in requests_list:
            ua = req.get("user_agent", "")
            ua_counts[ua] = ua_counts.get(ua, 0) + 1
        bot_kw     = {"scraper", "bot", "crawler", "spider", "harvester"}
        browser_kw = {"mozilla", "chrome", "safari", "firefox", "gecko", "webkit"}
        suspect_ua = None
        for ua, _ in sorted(ua_counts.items(), key=lambda x: -x[1]):
            if any(k in ua.lower() for k in bot_kw):
                suspect_ua = ua
                break
        if not suspect_ua:
            for ua, _ in sorted(ua_counts.items(), key=lambda x: -x[1]):
                if not any(k in ua.lower() for k in browser_kw):
                    suspect_ua = ua
                    break
        return {"action_type": "block_user_agent",
                "target_user_agent": suspect_ua or "ScraperBot/3.1"}

    else:
        return {"action_type": "write_custom_middleware",
                "regex_pattern": r"UNION\s+SELECT"}


# ─── LLM agent ────────────────────────────────────────────────────────────────

def _llm_action(task_id: str, obs: Dict[str, Any]) -> Dict[str, Any]:
    """Call the LiteLLM proxy supplied by the validator via API_BASE_URL / API_KEY."""
    inner_obs = obs.get("observation", obs)
    sample    = inner_obs.get("recent_requests", [])[:25]
    payload   = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": "You are an SRE. Return ONE firewall rule as JSON only. No prose."},
            {"role": "user",   "content": (
                f"TASK: {inner_obs.get('task_description','')}\n"
                f"HINT: {inner_obs.get('hint','')}\n"
                f"TRAFFIC: {json.dumps(sample)}\n"
                'JSON schema: {"action_type":"block_ip"|"block_user_agent"|"write_custom_middleware"|"add_rate_limit",'
                '"target_ip":"...","target_user_agent":"...","regex_pattern":"..."}'
            )},
        ],
        "max_tokens": 256,
        "temperature": 0.1,
    }).encode()
    # Always route through the validator-injected LiteLLM proxy endpoint
    llm_url = f"{LLM_BASE_URL}/chat/completions"
    req = urllib.request.Request(
        llm_url,
        data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {API_KEY}"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = json.loads(resp.read())["choices"][0]["message"]["content"].strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.lower().startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


# ─── Run one task episode ─────────────────────────────────────────────────────

def run_task(task_id: str) -> Dict[str, Any]:
    obs          = _post("/reset", {"task_id": task_id})
    score        = 0.0
    steps_taken  = 0
    step_results = []

    for step_num in range(1, 6):
        try:
            # Use LLM if a key is available (prefers validator-injected API_KEY)
            action = _llm_action(task_id, obs) if API_KEY else _heuristic_action(task_id, obs)
        except Exception:
            action = _heuristic_action(task_id, obs)

        result  = _post("/step", action)
        reward  = result.get("reward", {}).get("score", 0.0)
        done    = result.get("done", False)
        obs     = result
        score   = reward
        steps_taken = step_num
        step_results.append((step_num, reward))

        if done:
            break

    return {"task_id": task_id, "score": score,
            "steps": steps_taken, "step_results": step_results}


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    for task_id in TASK_IDS:
        print(f"[START] task={task_id}", flush=True)
        try:
            result = run_task(task_id)
            for step_num, reward in result["step_results"]:
                print(f"[STEP] step={step_num} reward={reward}", flush=True)
            print(f"[END] task={task_id} score={result['score']} steps={result['steps']}", flush=True)
        except Exception as exc:
            print(f"[STEP] step=1 reward=0.0", flush=True)
            print(f"[END] task={task_id} score=0.0 steps=1", flush=True)
            print(f"# ERROR: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
