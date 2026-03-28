---
title: Api Gateway Defender
emoji: 🏃
colorFrom: red
colorTo: red
sdk: docker
pinned: false
license: mit
tags:
  - openenv
---
# API Gateway Defender: OpenEnv Environment

## Environment Description and Motivation
"API Gateway Defender" simulates a live production incident for Site Reliability Engineers (SREs) and DevOps teams. The agent monitors a stream of simulated incoming HTTP requests to a Node.js/Express backend and must configure middleware rules to block malicious traffic while allowing legitimate users through. 

This environment tests an AI's ability to recognize algorithmic attack patterns (volumetric attacks, distributed scraping, and SQL injection) and write precise, deterministic filtering rules. It bridges the gap between simple text parsing and complex, real-world cybersecurity system management.

## Observation Space
The agent receives a JSON state containing:
* `recent_requests`: A list of dictionaries representing the last 100 HTTP requests. Keys include `ip`, `method`, `path`, `user_agent`, `query_string`, and `status_code`.
* `active_rules`: A list of currently applied middleware filtering rules.

## Action Space
The agent can execute one of three explicit actions:
* `add_rate_limit(target_ip)`: Blocks a specific IP address.
* `block_user_agent(target_user_agent)`: Drops traffic from a specific User-Agent string.
* `write_custom_middleware(regex_pattern)`: Applies a regex filter to the path and query string.

## Tasks and Expected Difficulty
1. **Easy (Volumetric Attack):** Identify and block a single IP making excessive requests to `/login`.
2. **Medium (Scraper Bot):** Identify a distributed scraping attack targeting `/api/data` across multiple IPs that share an obscure, identical User-Agent. Write a rule to block the User-Agent.
3. **Hard (Distributed SQLi):** An attacker rotates IPs and User-Agents, but all malicious requests contain a specific SQL injection payload in the `query_string`. The agent must deploy a custom regex middleware rule to drop these specific payloads.

## Reward Function and Grader Logic
The grader evaluates the agent's rules against a hidden test set of 1,000 requests (roughly 80% legitimate, 20% malicious). 
* **Score:** (Percentage of malicious requests blocked) - (Penalty for legitimate requests blocked).
* **Failure State:** If false positives (blocking legitimate users) exceed 10%, the score drops to 0.0.

## Setup and Usage Instructions
This environment is fully containerized via Docker and deployed on Hugging Face Spaces.
1. Send a POST request to `/reset` with `{"task_id": "easy"}` to initialize the state.
2. Retrieve the state via GET `/state`.
3. Submit an action via POST `/step` using the defined Action schema.
4. Retrieve the score via GET `/grader`.

## Baseline Scores
The baseline heuristic agent successfully achieves perfect scores across all tasks without triggering the false positive penalty.
* **Easy:** 1.000
* **Medium:** 1.000
* **Hard:** 1.000
