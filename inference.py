"""
Baseline Inference Script — API Gateway Defender
=================================================
Evaluates an agent on all 3 tasks and prints reproducible scores.

Usage
-----
  # With LLM (reads OPENAI_API_KEY from environment):
  OPENAI_API_KEY=sk-... python baseline.py

  # Heuristic fallback (no API key needed):
  python baseline.py

The LLM agent receives the traffic logs and task description, then
produces a JSON action that is submitted to the environment.

The heuristic agent reads the visible logs statistically and picks
the correct rule — used to verify the grader is working correctly
and as a reproducible baseline for submission.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict

# Allow running standalone (before FastAPI starts) by importing env directly
try:
    from env import (
        Action,
        APIGatewayDefender,
        TASK_DESCRIPTIONS,
        run_heuristic_baseline,
    )
    _DIRECT_IMPORT = True
except ImportError:
    _DIRECT_IMPORT = False

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ENV_BASE_URL   = os.getenv("ENV_BASE_URL", "http://localhost:8000")
LLM_MODEL      = os.getenv("LLM_MODEL", "gpt-4o-mini")


# ─── OpenAI helper ───────────────────────────────────────────────────────────────

def _call_openai(messages: list, max_tokens: int = 512) -> str:
    """Send a request to the OpenAI chat completions endpoint."""
    payload = json.dumps(
        {
            "model":       LLM_MODEL,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": 0.1,
        }
    ).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"OpenAI API error {exc.code}: {body}") from exc


def _parse_json_from_llm(raw: str) -> Dict[str, Any]:
    """Extract a JSON object from LLM output, stripping markdown fences if present."""
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        # parts[1] is the fenced block; strip language tag if present
        inner = parts[1]
        if inner.lower().startswith("json"):
            inner = inner[4:]
        raw = inner.strip()
    return json.loads(raw)


# ─── LLM agent ───────────────────────────────────────────────────────────────────

def _llm_agent_run(task_id: str) -> float:
    """
    Run an LLM agent on a single task via the HTTP API.

    1. Reset the environment.
    2. Show the agent the traffic logs and task description.
    3. Ask it to produce a JSON action.
    4. Submit the action and return the reward score.
    """
    import urllib.request as urlreq

    def _post(path: str, body: Any) -> Any:
        data = json.dumps(body).encode()
        req  = urlreq.Request(
            f"{ENV_BASE_URL}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urlreq.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    # 1. Reset
    obs = _post("/reset", {"task_id": task_id})

    # 2. Build prompt (truncate request list to 25 to stay within token budget)
    sample_requests = obs["recent_requests"][:25]

    system_prompt = (
        "You are a Site Reliability Engineer responding to a live production incident. "
        "You will be shown HTTP traffic logs and a task description. "
        "Your job is to write exactly ONE firewall rule as a JSON object. "
        "Respond with ONLY valid JSON — no prose, no markdown fences."
    )

    action_schema = (
        "{\n"
        '  "action_type": "block_ip" | "add_rate_limit" | "block_user_agent" | "write_custom_middleware",\n'
        '  "target_ip":          "<string, required for block_ip / add_rate_limit>",\n'
        '  "target_user_agent":  "<string, required for block_user_agent>",\n'
        '  "regex_pattern":      "<Python regex, required for write_custom_middleware>",\n'
        '  "max_requests":       <int, optional — requests/min cap for add_rate_limit>\n'
        "}"
    )

    user_prompt = (
        f"TASK: {obs['task_description']}\n\n"
        f"HINT: {obs.get('hint', '')}\n\n"
        f"TRAFFIC SAMPLE (first 25 requests):\n"
        f"{json.dumps(sample_requests, indent=2)}\n\n"
        f"Respond with ONE JSON action using this schema:\n{action_schema}"
    )

    # 3. Call LLM
    llm_response = _call_openai(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ]
    )

    # 4. Parse action
    try:
        action_dict = _parse_json_from_llm(llm_response)
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"    [!] Failed to parse LLM response: {exc}\n    Raw: {llm_response[:200]}")
        return 0.0

    # 5. Step
    result = _post("/step", action_dict)
    score  = result["reward"]["score"]
    msg    = result["reward"]["message"]
    print(f"    Action:  {action_dict}")
    print(f"    Result:  {msg}")
    return score


# ─── Main ────────────────────────────────────────────────────────────────────────

def run_baseline_direct() -> Dict[str, float]:
    """Run heuristic baseline directly on the Python class (no server needed)."""
    return run_heuristic_baseline()


def run_baseline_http() -> Dict[str, float]:
    """Run heuristic baseline via the HTTP API."""
    import urllib.request as urlreq

    req = urlreq.Request(
        f"{ENV_BASE_URL}/baseline",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlreq.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["scores"]


def main() -> None:
    print("=" * 55)
    print("  API Gateway Defender — Baseline Evaluation")
    print("=" * 55)
    print()

    task_ids = ["easy", "medium", "hard"]
    scores:   Dict[str, float] = {}

    if OPENAI_API_KEY:
        print(f"Mode : LLM agent  ({LLM_MODEL})")
        print(f"URL  : {ENV_BASE_URL}")
        print()
        for task_id in task_ids:
            print(f"[Task: {task_id}]")
            try:
                score = _llm_agent_run(task_id)
                scores[task_id] = score
                print(f"    Score: {score:.4f}")
            except Exception as exc:
                print(f"    [!] Error: {exc}. Falling back to heuristic.")
                if _DIRECT_IMPORT:
                    fb = run_heuristic_baseline()
                    scores[task_id] = fb.get(task_id, 0.0)
                else:
                    scores[task_id] = 0.0
            print()
    else:
        print("Mode : Heuristic agent  (set OPENAI_API_KEY to use LLM)")
        print()
        if _DIRECT_IMPORT:
            scores = run_baseline_direct()
        else:
            print(f"Calling {ENV_BASE_URL}/baseline ...")
            scores = run_baseline_http()
        for task_id in task_ids:
            print(f"  [{task_id}]  score = {scores.get(task_id, 0.0):.4f}")

    print()
    print("-" * 35)
    avg = sum(scores.values()) / max(len(scores), 1)
    for task_id in task_ids:
        s = scores.get(task_id, 0.0)
        bar = "█" * int(s * 20)
        print(f"  {task_id:<8s}  {s:.4f}  {bar}")
    print(f"  {'average':<8s}  {avg:.4f}")
    print("-" * 35)
    print()

    # Exit non-zero if any task scored 0.0 (helps CI catch broken graders)
    if any(v == 0.0 for v in scores.values()):
        print("[WARN] One or more tasks scored 0.0. Check the environment.")
        sys.exit(1)
    else:
        print("[OK] All tasks passed baseline threshold.")


if __name__ == "__main__":
    main()
