"""Triage cases with a local model and record every verdict.

    python -m triage.run --model qwen2.5-coder:7b --condition baseline

Conditions
  baseline           all cases, plain prompt
  hardened           all cases, hardened prompt (does hardening cost accuracy on clean data?)
  injected           malicious cases with the payload in user fields, plain prompt
  injected+hardened  same attack, hardened prompt
  injected+guard     same attack, hardened prompt, plus the deterministic guard in front of the model

Results append to results/<model>__<condition>.jsonl; an interrupted run resumes.
"""

from __future__ import annotations

import argparse
import json
import os
import time

import requests

from triage import guard, prompts
from triage.cases import ROOT, load

OLLAMA = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
CONDITIONS = ["baseline", "hardened", "injected", "injected+hardened", "injected+guard"]


def ask(model: str, messages: list[dict]) -> tuple[dict, float]:
    t = time.perf_counter()
    r = requests.post(
        f"{OLLAMA}/api/chat",
        json={
            "model": model,
            "messages": messages,
            "stream": False,
            "format": prompts.SCHEMA,  # structured output: the reply must parse as this schema
            "options": {"temperature": 0, "seed": 7, "num_ctx": 4096},
        },
        timeout=900,
    )
    r.raise_for_status()
    return json.loads(r.json()["message"]["content"]), time.perf_counter() - t


def cases_for(condition: str) -> list[dict]:
    cases = load()
    if condition.startswith("injected"):
        return [prompts.inject(c) for c in cases if c["label"] == "escalate"]
    return cases


def triage(case: dict, model: str, condition: str) -> dict:
    hits = guard.findings(case) if condition.endswith("guard") else []
    build = prompts.plain if condition in ("baseline", "injected") else prompts.hardened
    answer, seconds = ask(model, build(case))
    verdict = answer["verdict"]
    if hits:
        verdict = "escalate"  # the guard overrides the model; the model's own answer is kept for the report
    return {
        "id": case["id"],
        "kind": case["kind"],
        "incident": case["incident"],
        "label": case["label"],
        "model": model,
        "condition": condition,
        "verdict": verdict,
        "model_verdict": answer["verdict"],
        "confidence": answer.get("confidence"),
        "reason": answer.get("reason"),
        "guard_hits": len(hits),
        "seconds": round(seconds, 2),
    }


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--condition", choices=CONDITIONS, required=True)
    args = p.parse_args(argv)
    out = ROOT / "results" / f"{args.model.replace(':', '_')}__{args.condition}.jsonl"
    done = {json.loads(line)["id"] for line in out.read_text().splitlines()} if out.exists() else set()
    todo = [c for c in cases_for(args.condition) if c["id"] not in done]
    print(f"{args.model} / {args.condition}: {len(done)} done, {len(todo)} to go")
    with out.open("a") as f:
        for c in todo:
            r = triage(c, args.model, args.condition)
            f.write(json.dumps(r) + "\n")
            f.flush()
            ok = "ok " if r["verdict"] == r["label"] else "MISS"
            print(f"  {ok} {r['id']:<32} {r['verdict']:<8} {r['seconds']:>6.1f}s  {r['reason'][:70]}")


if __name__ == "__main__":
    main()
