"""
API Gateway Defender — FastAPI Server
=====================================
Exposes the OpenEnv-compliant HTTP API for the environment.

Endpoints
---------
  POST /reset       — Start a new episode
  POST /step        — Submit a firewall rule, receive reward
  GET  /state       — Inspect current environment state
  GET  /tasks       — List tasks and action schema
  GET  /grader      — Get grader score for current episode
  POST /baseline    — Run heuristic baseline across all 3 tasks
  GET  /health      — Liveness probe (required for HF Spaces ping)
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, Optional
from pydantic import BaseModel

from env import (
    Action,
    APIGatewayDefender,
    Observation,
    TASK_DESCRIPTIONS,
    run_heuristic_baseline,
)

# ─── App setup ───────────────────────────────────────────────────────────────────

app = FastAPI(
    title="API Gateway Defender",
    description=(
        "An OpenEnv RL environment where an AI agent defends a simulated web backend "
        "against volumetric floods, scraper bots, and SQL injection attacks."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single shared environment instance (stateful, per-session)
_env = APIGatewayDefender()


class ResetRequest(BaseModel):
    task_id: str = "easy"


# ─── Routes ──────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> Dict[str, str]:
    """Liveness probe — returns 200 and confirms the environment is running."""
    return {"status": "ok", "environment": "api-gateway-defender"}


@app.get("/")
def root() -> Dict[str, Any]:
    """Overview of the environment and available endpoints."""
    return {
        "name": "API Gateway Defender",
        "description": (
            "OpenEnv RL environment: configure firewall rules to block malicious "
            "HTTP traffic while preserving legitimate requests."
        ),
        "version": "1.0.0",
        "tasks": list(TASK_DESCRIPTIONS.keys()),
        "endpoints": {
            "POST /reset":    "Start a new episode. Body: {task_id: 'easy'|'medium'|'hard'}",
            "POST /step":     "Submit a firewall rule. Body: Action schema.",
            "GET  /state":    "Current environment state snapshot.",
            "GET  /tasks":    "Task descriptions + action/observation schemas.",
            "GET  /grader":   "Current grader score for the active episode.",
            "POST /baseline": "Run heuristic baseline agent across all 3 tasks.",
            "GET  /health":   "Liveness probe.",
        },
    }


@app.post("/reset")
async def reset(
    req: Optional[ResetRequest] = None,
    task_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Start a new episode.

    Accepts ALL of these formats (validator may use any):
      - JSON body:    {"task_id": "easy"}
      - Query param:  POST /reset?task_id=easy
      - Empty body:   POST /reset  (defaults to "easy")
      - No body at all: POST /reset  (defaults to "easy")
    """
    # Priority: JSON body > query param > default "easy"
    tid = (req.task_id if req else None) or task_id or "easy"
    try:
        obs: Observation = _env.reset(task_id=tid)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return obs.model_dump()


@app.post("/step")
def step(action: Action) -> Dict[str, Any]:
    """
    Submit one firewall rule.

    Returns StepResult: {observation, reward, done, info}

    Reward score: 0.0–1.0
      = detection_rate − (false_positive_rate × 5)
      = 0.0 if false positive rate > 10%
    """
    try:
        result = _env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result.model_dump()


@app.get("/state")
def state() -> Dict[str, Any]:
    """Return the full serialisable state of the current episode."""
    return _env.state().model_dump()


@app.get("/tasks")
def tasks() -> Dict[str, Any]:
    """
    List all tasks and their descriptions, plus the action and observation schemas.
    Required by the OpenEnv spec.
    """
    return {
        "tasks": [
            {
                "id":          "easy",
                "name":        "Volumetric IP Flood Defense",
                "difficulty":  "easy",
                "description": TASK_DESCRIPTIONS["easy"],
                "hint":        "One IP is responsible for all malicious traffic.",
            },
            {
                "id":          "medium",
                "name":        "Scraper Bot Detection",
                "difficulty":  "medium",
                "description": TASK_DESCRIPTIONS["medium"],
                "hint":        "Many IPs, but a single shared User-Agent string.",
            },
            {
                "id":          "hard",
                "name":        "SQL Injection Middleware Defense",
                "difficulty":  "hard",
                "description": TASK_DESCRIPTIONS["hard"],
                "hint":        "Rotating IPs and UAs, but a consistent payload pattern.",
            },
        ],
        "action_schema":      Action.model_json_schema(),
        "observation_schema": {
            "recent_requests": "list[dict] — last 100 requests: ip, method, path, user_agent, query_string, status_code",
            "active_rules":    "list[str] — human-readable active firewall rules",
            "current_task":    "str — 'easy', 'medium', or 'hard'",
            "task_description":"str — natural language goal",
            "step_count":      "int — steps taken this episode",
            "hint":            "str — statistical hint from visible traffic",
        },
    }


@app.get("/grader")
def grader() -> Dict[str, Any]:
    """
    Return the programmatic grader score for the current episode.
    Score is 0.0–1.0; reflects detection rate minus false-positive penalty.
    """
    score      = _env.get_task_grader_score()
    state_info = _env.state()
    return {
        "task_id":      state_info.task_id,
        "score":        score,
        "best_score":   state_info.best_score,
        "rules_applied":[r["description"] for r in state_info.active_rules],
        "episode_done": state_info.episode_done,
        "max_steps":    5,
    }


@app.post("/baseline")
def baseline() -> Dict[str, Any]:
    """
    Run the heuristic baseline agent across all 3 tasks and return scores.
    Does not affect the shared episode state.
    """
    scores = run_heuristic_baseline()
    avg    = sum(scores.values()) / len(scores)
    return {
        "scores":  scores,
        "average": round(avg, 4),
        "message": (
            "Heuristic baseline: reads visible logs, identifies the attack pattern, "
            "applies the optimal rule. No LLM required."
        ),
    }
