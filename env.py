"""
API Gateway Defender — OpenEnv Environment
==========================================
A simulated HTTP traffic monitoring environment where an AI agent must
configure middleware rules to block malicious web traffic while preserving
legitimate user requests. Models a real production incident faced by SREs.

Tasks:
  easy   — Single IP volumetric flood on /login
  medium — Scraper bot using identical User-Agent across many IPs
  hard   — SQL injection attack with rotating IPs and User-Agents
"""

import re
import random
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ─── Constants ──────────────────────────────────────────────────────────────────

MAX_STEPS = 5
TRAFFIC_SIZE = 1000
MALICIOUS_COUNT = 200
FALSE_POSITIVE_THRESHOLD = 0.10   # >10% FP rate → score zeroed

# Fixed attack artifacts (deterministic so graders are reproducible)
ATTACK_IP_EASY   = "185.220.101.47"
SCRAPER_UA       = "ScraperBot/3.1 (DataHarvester; +http://scrape.evil.io/bot)"
SQLI_KEYWORD     = "UNION SELECT"

LEGIT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/115.0",
]

LEGIT_PATHS = [
    "/", "/home", "/about", "/products", "/contact",
    "/blog", "/faq", "/pricing", "/docs", "/api/users", "/api/products",
]

LEGIT_QUERY_STRINGS = [
    "", "page=1", "q=hello", "id=42", "sort=asc&filter=new",
    "utm_source=google", "lang=en", "category=tech", "ref=nav",
]

LEGIT_METHODS = ["GET", "GET", "GET", "POST", "PUT"]  # GET-heavy, realistic

SQLI_PAYLOADS = [
    f"id=1' {SQLI_KEYWORD} username,password FROM users--",
    f"search=admin' {SQLI_KEYWORD} 1,2,3--",
    f"q=x' {SQLI_KEYWORD} table_name FROM information_schema.tables--",
    f"cat=1' {SQLI_KEYWORD} NULL,NULL,NULL--",
    f"item=5' {SQLI_KEYWORD} version()--",
]

# ─── Pydantic Models ─────────────────────────────────────────────────────────────

class Action(BaseModel):
    """
    An action the agent can take — adds one firewall rule to the gateway.

    action_type choices:
      block_ip               — Drop all traffic from target_ip
      add_rate_limit         — Allow target_ip only max_requests/min
      block_user_agent       — Drop all traffic matching target_user_agent exactly
      write_custom_middleware — Drop requests where regex_pattern matches path?query_string
    """
    action_type: str = Field(
        ...,
        description=(
            "Rule type: 'block_ip', 'add_rate_limit', "
            "'block_user_agent', 'write_custom_middleware'"
        ),
    )
    target_ip: Optional[str] = Field(
        None, description="IP address (required for block_ip / add_rate_limit)"
    )
    target_user_agent: Optional[str] = Field(
        None, description="Exact User-Agent string (required for block_user_agent)"
    )
    regex_pattern: Optional[str] = Field(
        None,
        description=(
            "Python regex matched against '{path}?{query_string}' "
            "(required for write_custom_middleware)"
        ),
    )
    max_requests: Optional[int] = Field(
        60, description="Requests-per-minute cap for add_rate_limit (default 60)"
    )


class Observation(BaseModel):
    """What the agent sees at each step."""
    recent_requests: List[Dict[str, Any]] = Field(
        ...,
        description=(
            "Last 100 HTTP requests in the traffic stream. "
            "Fields: ip, method, path, user_agent, query_string, status_code."
        ),
    )
    active_rules: List[str] = Field(
        ..., description="Human-readable list of rules currently active on the gateway."
    )
    current_task: str = Field(..., description="Task ID: 'easy', 'medium', or 'hard'")
    task_description: str = Field(
        ..., description="Natural language description of the attack the agent must repel."
    )
    step_count: int = Field(..., description="Number of rules submitted so far this episode.")
    hint: str = Field("", description="Statistical hint derived from the visible traffic sample.")


class Reward(BaseModel):
    """Feedback returned after each step()."""
    score: float = Field(..., ge=0.0, le=1.0, description="Task performance score 0.0–1.0")
    malicious_blocked: int = Field(..., description="Malicious requests blocked by active rules")
    legitimate_blocked: int = Field(..., description="Legitimate requests incorrectly blocked")
    total_malicious: int
    total_legitimate: int
    false_positive_rate: float = Field(..., description="Fraction of legit requests blocked")
    message: str = Field(..., description="Human-readable explanation of the score")


class StepResult(BaseModel):
    """Full return value of step()."""
    observation: Observation
    reward: Reward
    done: bool
    info: Dict[str, Any]


class EnvironmentState(BaseModel):
    """Full serialisable snapshot returned by state()."""
    task_id: str
    step_count: int
    active_rules: List[Dict[str, Any]]
    episode_done: bool
    best_score: float
    traffic_sample_size: int


# ─── Traffic Generators ──────────────────────────────────────────────────────────

def _rand_ip(rng: random.Random, exclude: str = "") -> str:
    """Generate a random public-looking IPv4 address."""
    while True:
        ip = (
            f"{rng.randint(10, 220)}."
            f"{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}"
        )
        if ip != exclude:
            return ip


def _legit_request(rng: random.Random) -> Dict[str, Any]:
    return {
        "ip":           _rand_ip(rng, exclude=ATTACK_IP_EASY),
        "method":       rng.choice(LEGIT_METHODS),
        "path":         rng.choice(LEGIT_PATHS),
        "user_agent":   rng.choice(LEGIT_USER_AGENTS),
        "query_string": rng.choice(LEGIT_QUERY_STRINGS),
        "status_code":  200,
        "is_malicious": False,
    }


def generate_easy_traffic(seed: int) -> List[Dict[str, Any]]:
    """
    Easy: one IP floods /login with POST requests.
    Correct action: block_ip or add_rate_limit on ATTACK_IP_EASY.
    """
    rng = random.Random(seed)
    traffic: List[Dict[str, Any]] = []

    for _ in range(MALICIOUS_COUNT):
        traffic.append({
            "ip":           ATTACK_IP_EASY,
            "method":       "POST",
            "path":         "/login",
            "user_agent":   rng.choice(LEGIT_USER_AGENTS),  # UA blends in
            "query_string": "",
            "status_code":  200,
            "is_malicious": True,
        })

    for _ in range(TRAFFIC_SIZE - MALICIOUS_COUNT):
        traffic.append(_legit_request(rng))

    rng.shuffle(traffic)
    return traffic


def generate_medium_traffic(seed: int) -> List[Dict[str, Any]]:
    """
    Medium: 50 IPs all share an identical unusual User-Agent, hitting /api/data.
    Correct action: block_user_agent with SCRAPER_UA.
    """
    rng = random.Random(seed)
    traffic: List[Dict[str, Any]] = []

    scraper_ips = [_rand_ip(rng) for _ in range(50)]
    for _ in range(MALICIOUS_COUNT):
        traffic.append({
            "ip":           rng.choice(scraper_ips),
            "method":       "GET",
            "path":         "/api/data",
            "user_agent":   SCRAPER_UA,   # constant across all malicious requests
            "query_string": f"page={rng.randint(1, 500)}",
            "status_code":  200,
            "is_malicious": True,
        })

    for _ in range(TRAFFIC_SIZE - MALICIOUS_COUNT):
        traffic.append(_legit_request(rng))

    rng.shuffle(traffic)
    return traffic


def generate_hard_traffic(seed: int) -> List[Dict[str, Any]]:
    """
    Hard: attacker rotates IPs and UAs but always carries a SQLi payload.
    Correct action: write_custom_middleware with regex matching 'UNION.SELECT'.
    """
    rng = random.Random(seed)
    traffic: List[Dict[str, Any]] = []

    for _ in range(MALICIOUS_COUNT):
        traffic.append({
            "ip":           _rand_ip(rng),
            "method":       "GET",
            "path":         rng.choice(["/search", "/products", "/api/items", "/catalog"]),
            "user_agent":   rng.choice(LEGIT_USER_AGENTS),
            "query_string": rng.choice(SQLI_PAYLOADS),
            "status_code":  200,
            "is_malicious": True,
        })

    for _ in range(TRAFFIC_SIZE - MALICIOUS_COUNT):
        req = _legit_request(rng)
        # Guarantee legit requests never accidentally contain the payload
        if SQLI_KEYWORD in req["query_string"].upper():
            req["query_string"] = ""
        traffic.append(req)

    rng.shuffle(traffic)
    return traffic


TASK_GENERATORS = {
    "easy":   generate_easy_traffic,
    "medium": generate_medium_traffic,
    "hard":   generate_hard_traffic,
}

TASK_DESCRIPTIONS = {
    "easy": (
        "A single IP address is flooding your /login endpoint with POST requests at high volume. "
        "Inspect the traffic logs to identify the offending IP and block it or apply a rate limit."
    ),
    "medium": (
        "A scraper bot is harvesting your /api/data endpoint from many different IP addresses. "
        "All malicious requests share a single, unusual User-Agent string. "
        "Identify the User-Agent and block it."
    ),
    "hard": (
        "An attacker is probing your database via SQL injection. They rotate IP addresses and "
        "User-Agents to evade simple rules, but every malicious request contains a SQL injection "
        "payload in the query string. Write a regex middleware rule to detect and drop these requests."
    ),
}


# ─── Rule Engine ─────────────────────────────────────────────────────────────────

class _Rule:
    """Internal class: wraps an Action and applies it to individual requests."""

    def __init__(self, action: Action) -> None:
        self.action = action
        self._compiled_re = None
        if action.action_type == "write_custom_middleware" and action.regex_pattern:
            try:
                self._compiled_re = re.compile(action.regex_pattern, re.IGNORECASE)
            except re.error:
                pass  # invalid regex → rule matches nothing

    def blocks(self, request: Dict[str, Any]) -> bool:
        a = self.action
        if a.action_type in ("block_ip", "add_rate_limit"):
            return bool(a.target_ip and request["ip"] == a.target_ip)
        if a.action_type == "block_user_agent":
            return bool(
                a.target_user_agent
                and request["user_agent"] == a.target_user_agent
            )
        if a.action_type == "write_custom_middleware" and self._compiled_re:
            target = f"{request['path']}?{request['query_string']}"
            return bool(self._compiled_re.search(target))
        return False

    def describe(self) -> str:
        a = self.action
        if a.action_type == "block_ip":
            return f"BLOCK_IP({a.target_ip})"
        if a.action_type == "add_rate_limit":
            return f"RATE_LIMIT({a.target_ip}, max={a.max_requests}/min)"
        if a.action_type == "block_user_agent":
            return f"BLOCK_UA({a.target_user_agent!r})"
        if a.action_type == "write_custom_middleware":
            return f"MIDDLEWARE(regex={a.regex_pattern!r})"
        return f"RULE({a.action_type})"

    def to_dict(self) -> Dict[str, Any]:
        a = self.action
        return {
            "action_type":       a.action_type,
            "target_ip":         a.target_ip,
            "target_user_agent": a.target_user_agent,
            "regex_pattern":     a.regex_pattern,
            "description":       self.describe(),
        }


# ─── Environment ─────────────────────────────────────────────────────────────────

VALID_ACTION_TYPES = {"block_ip", "add_rate_limit", "block_user_agent", "write_custom_middleware"}


class APIGatewayDefender:
    """
    OpenEnv-compliant RL environment — API Gateway Defender.

    The agent monitors a simulated stream of HTTP requests and must apply
    firewall middleware rules to block malicious traffic while preserving
    legitimate requests.

    Usage
    -----
        env = APIGatewayDefender()
        obs = env.reset(task_id="easy")
        action = Action(action_type="block_ip", target_ip="185.220.101.47")
        result = env.step(action)
        print(result.reward.score)
    """

    def __init__(self) -> None:
        self._task_id: str = "easy"
        self._rules: List[_Rule] = []
        self._train_traffic: List[Dict[str, Any]] = []
        self._test_traffic: List[Dict[str, Any]] = []
        self._step_count: int = 0
        self._done: bool = False
        self._best_score: float = 0.0

    # ── OpenEnv Interface ──────────────────────────────────────────────────────

    def reset(self, task_id: str = "easy") -> Observation:
        """
        Start a new episode on the given task.

        Parameters
        ----------
        task_id : str
            One of 'easy', 'medium', 'hard'.

        Returns
        -------
        Observation
            Initial observation containing the first 100 traffic samples.
        """
        if task_id not in TASK_GENERATORS:
            raise ValueError(
                f"Unknown task_id '{task_id}'. Choose from: {sorted(TASK_GENERATORS)}"
            )
        self._task_id = task_id
        self._rules = []
        self._step_count = 0
        self._done = False
        self._best_score = 0.0

        gen = TASK_GENERATORS[task_id]
        self._train_traffic = gen(seed=42)   # agent can see this
        self._test_traffic  = gen(seed=137)  # grading set (hidden from agent)

        return self._make_observation()

    def step(self, action: Action) -> StepResult:
        """
        Submit one firewall rule and receive a reward signal.

        The rule is evaluated against a hidden test traffic set to prevent
        overfitting to the visible sample. Partial credit is awarded for
        partial detection; false positives incur a penalty.

        Parameters
        ----------
        action : Action
            The rule to apply.

        Returns
        -------
        StepResult
            observation, reward, done flag, and diagnostic info.
        """
        if self._done:
            raise RuntimeError("Episode is finished. Call reset() to start a new episode.")

        self._step_count += 1

        # ── Validate action type ──────────────────────────────────────────────
        if action.action_type not in VALID_ACTION_TYPES:
            err_reward = Reward(
                score=0.0,
                malicious_blocked=0,
                legitimate_blocked=0,
                total_malicious=MALICIOUS_COUNT,
                total_legitimate=TRAFFIC_SIZE - MALICIOUS_COUNT,
                false_positive_rate=0.0,
                message=(
                    f"Invalid action_type '{action.action_type}'. "
                    f"Must be one of {sorted(VALID_ACTION_TYPES)}."
                ),
            )
            return StepResult(
                observation=self._make_observation(),
                reward=err_reward,
                done=False,
                info={"error": "invalid_action_type"},
            )

        # ── Apply rule ────────────────────────────────────────────────────────
        self._rules.append(_Rule(action))

        # ── Grade on hidden test traffic ──────────────────────────────────────
        reward = self._grade()
        self._best_score = max(self._best_score, reward.score)

        # Episode ends at MAX_STEPS or when the agent achieves near-perfect score
        self._done = self._step_count >= MAX_STEPS or reward.score >= 0.95

        return StepResult(
            observation=self._make_observation(),
            reward=reward,
            done=self._done,
            info={
                "step":          self._step_count,
                "best_score":    self._best_score,
                "rules_applied": [r.describe() for r in self._rules],
                "max_steps":     MAX_STEPS,
            },
        )

    def state(self) -> EnvironmentState:
        """Return a full serialisable snapshot of the current environment state."""
        return EnvironmentState(
            task_id=self._task_id,
            step_count=self._step_count,
            active_rules=[r.to_dict() for r in self._rules],
            episode_done=self._done,
            best_score=self._best_score,
            traffic_sample_size=len(self._train_traffic),
        )

    def get_task_grader_score(self) -> float:
        """
        Programmatic grader — returns score strictly in (0, 1) for the current episode.
        Returns the minimum non-zero score if no rules have been applied yet.
        """
        if not self._rules:
            return 0.001
        return self._grade().score

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _make_observation(self) -> Observation:
        """Build an Observation from the current state (no is_malicious flag exposed)."""
        visible = [
            {k: v for k, v in req.items() if k != "is_malicious"}
            for req in self._train_traffic[:100]
        ]
        return Observation(
            recent_requests=visible,
            active_rules=[r.describe() for r in self._rules],
            current_task=self._task_id,
            task_description=TASK_DESCRIPTIONS[self._task_id],
            step_count=self._step_count,
            hint=self._build_hint(),
        )

    def _build_hint(self) -> str:
        """Generate a statistical hint from the visible traffic sample."""
        if not self._train_traffic:
            return ""
        sample = self._train_traffic[:100]
        malicious_in_sample = [r for r in sample if r.get("is_malicious")]
        n = len(malicious_in_sample)

        if self._task_id == "easy":
            if n == 0:
                return "Traffic looks normal in this window."
            ips = {r["ip"] for r in malicious_in_sample}
            return (
                f"Warning: {n} POST requests to /login detected in this window "
                f"from {len(ips)} unique IP(s). Possible brute-force or flood."
            )
        elif self._task_id == "medium":
            if n == 0:
                return "Traffic looks normal in this window."
            uas = {r["user_agent"] for r in malicious_in_sample}
            return (
                f"Warning: {n} requests to /api/data share {len(uas)} unique User-Agent(s) "
                f"in this window. Possible scraper activity."
            )
        else:
            if n == 0:
                return "Traffic looks normal in this window."
            return (
                f"Warning: {n} requests in this window contain unusual query string patterns. "
                f"Check for injection payloads."
            )

    # Validator requires scores strictly between 0 and 1 (exclusive)
    _SCORE_MIN = 0.001
    _SCORE_MAX = 0.999

    def _grade(self) -> Reward:
        """
        Apply all active rules to the hidden test traffic set and compute a score.

        Score formula:
            detection_rate = malicious_blocked / total_malicious
            fp_rate        = legitimate_blocked / total_legitimate
            if fp_rate > FALSE_POSITIVE_THRESHOLD:
                score = _SCORE_MIN   ← too many false positives
            else:
                score = clamp(detection_rate - fp_rate * 5.0, _SCORE_MIN, _SCORE_MAX)

        The final score is always strictly in (0, 1) as required by the validator.
        """
        malicious = [r for r in self._test_traffic if r["is_malicious"]]
        legit     = [r for r in self._test_traffic if not r["is_malicious"]]

        mal_blocked   = sum(1 for r in malicious if any(rule.blocks(r) for rule in self._rules))
        legit_blocked = sum(1 for r in legit     if any(rule.blocks(r) for rule in self._rules))

        total_mal   = len(malicious)
        total_legit = len(legit)

        detection_rate = mal_blocked  / total_mal   if total_mal   > 0 else 0.0
        fp_rate        = legit_blocked / total_legit if total_legit > 0 else 0.0

        if fp_rate > FALSE_POSITIVE_THRESHOLD:
            score = self._SCORE_MIN
            message = (
                f"Score floored: {fp_rate:.1%} false positive rate exceeds "
                f"{FALSE_POSITIVE_THRESHOLD:.0%} threshold. Rules are too broad — "
                f"legitimate users are being blocked."
            )
        else:
            raw   = detection_rate - fp_rate * 5.0
            score = max(self._SCORE_MIN, min(self._SCORE_MAX, raw))
            message = (
                f"Blocked {mal_blocked}/{total_mal} malicious requests "
                f"({detection_rate:.1%} detection rate) with "
                f"{fp_rate:.1%} false positive rate."
            )

        return Reward(
            score=round(score, 4),
            malicious_blocked=mal_blocked,
            legitimate_blocked=legit_blocked,
            total_malicious=total_mal,
            total_legitimate=total_legit,
            false_positive_rate=round(fp_rate, 4),
            message=message,
        )


# ─── Convenience: heuristic baseline that runs directly on the class ────────────

def run_heuristic_baseline() -> Dict[str, float]:
    """
    A deterministic heuristic agent that solves all 3 tasks correctly.
    Used by the /baseline endpoint and as fallback in the inference script.

    Returns
    -------
    Dict[str, float]
        task_id → score
    """
    env = APIGatewayDefender()
    scores: Dict[str, float] = {}

    # ── Easy: identify the IP flooding /login ──────────────────────────────────
    obs = env.reset("easy")
    ip_counts: Dict[str, int] = {}
    for req in obs.recent_requests:
        if req["path"] == "/login" and req["method"] == "POST":
            ip_counts[req["ip"]] = ip_counts.get(req["ip"], 0) + 1
    suspect_ip = (
        max(ip_counts, key=lambda k: ip_counts[k]) if ip_counts else ATTACK_IP_EASY
    )
    result = env.step(Action(action_type="block_ip", target_ip=suspect_ip))
    scores["easy"] = result.reward.score

    # ── Medium: identify the unusual User-Agent ────────────────────────────────
    obs = env.reset("medium")
    ua_counts: Dict[str, int] = {}
    for req in obs.recent_requests:
        ua_counts[req["user_agent"]] = ua_counts.get(req["user_agent"], 0) + 1

    bot_keywords = {"scraper", "bot", "crawler", "spider", "harvester"}
    browser_keywords = {"mozilla", "chrome", "safari", "firefox", "gecko", "webkit"}
    suspect_ua = None

    # Prefer UAs that look like bots
    for ua, _ in sorted(ua_counts.items(), key=lambda x: -x[1]):
        if any(k in ua.lower() for k in bot_keywords):
            suspect_ua = ua
            break
    # Fallback: most common UA that doesn't look like a browser
    if not suspect_ua:
        for ua, _ in sorted(ua_counts.items(), key=lambda x: -x[1]):
            if not any(k in ua.lower() for k in browser_keywords):
                suspect_ua = ua
                break

    result = env.step(Action(action_type="block_user_agent", target_user_agent=suspect_ua or ""))
    scores["medium"] = result.reward.score

    # ── Hard: write a regex to catch SQLi payloads ────────────────────────────
    env.reset("hard")
    result = env.step(
        Action(
            action_type="write_custom_middleware",
            regex_pattern=r"UNION\s+SELECT",
        )
    )
    scores["hard"] = result.reward.score

    return scores
