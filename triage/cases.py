"""Build the evaluation cases: one per host-hour, the unit an analyst investigates.

Labels come from the generator's ground truth in soc-alert-analytics:
  malicious  the host-hour contains at least one planted attack alert
  benign     no planted alert, and the simulated analysts escalated nothing in it
Host-hours with no planted alert but an analyst escalation are left out: the background noise
includes real-looking high-severity alerts, and calling those "wrong to escalate" would be unfair.

Benign cases come in two kinds: "hard" (the busiest, most severe benign hours, the ones that cost
analysts time) and "easy" (a seeded random sample of the rest).

    python -m triage.cases
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
SOC = Path(os.getenv("SOC_REPO", ROOT.parent / "soc-alert-analytics"))
OUT = ROOT / "cases" / "cases.jsonl"
HARD, EASY = 60, 40

HOURS_SQL = """
with h as (
    select agent, date_trunc('hour', ts) as hour,
           count(*) as alerts,
           max(level) as max_level,
           count(distinct rule_id) as rules,
           bool_or(alert_id in (select id from planted)) as has_planted,
           bool_or(alert_id in (select alert_id from triage where escalated)) as analyst_escalated
    from alerts group by 1, 2
)
select * from h order by agent, hour
"""

ALERTS_SQL = """
select ts, rule_id, level, rule_description, mitre_technique, mitre_tactic, src_ip, src_user, dst_user
from alerts where agent = ? and date_trunc('hour', ts) = ? order by ts
"""


def summarise(alerts: list[tuple]) -> dict:
    """What an analyst sees first: counts per rule, then the distinct actors, then a few raw alerts."""
    by_rule: dict[tuple, int] = {}
    for a in alerts:
        key = (a[1], a[2], a[3], a[5] or "")
        by_rule[key] = by_rule.get(key, 0) + 1
    rules = [
        {"rule_id": r, "level": lvl, "description": d, "tactic": t, "count": n}
        for (r, lvl, d, t), n in sorted(by_rule.items(), key=lambda kv: (-kv[0][1], -kv[1]))
    ]
    distinct = lambda i: sorted({a[i] for a in alerts if a[i]})  # noqa: E731
    return {
        "alert_count": len(alerts),
        "rules": rules,
        "source_ips": distinct(6)[:15],
        "source_users": distinct(7)[:15],
        "target_users": distinct(8)[:15],
        "first_alerts": [
            {
                "time": a[0].strftime("%H:%M:%S"),
                "rule_id": a[1],
                "level": a[2],
                "description": a[3],
                "src_ip": a[6],
                "src_user": a[7],
                "dst_user": a[8],
            }
            for a in alerts[:8]
        ],
    }


def main() -> None:
    con = duckdb.connect(str(SOC / "data/soc.duckdb"), read_only=True)
    con.execute("SET TimeZone = 'UTC'")  # hours must match the generator's UTC incident times on any machine
    planted = json.loads((SOC / "data/planted.json").read_text())
    con.execute("create temp table planted (id varchar)")
    con.executemany("insert into planted values (?)", [(i,) for i in planted["planted_alert_ids"]])
    hours = con.execute(HOURS_SQL).fetchall()

    malicious = [h for h in hours if h[5]]
    benign = [h for h in hours if not h[5] and not h[6]]
    benign.sort(key=lambda h: (-h[3], -h[4], -h[2]))  # most severe, most varied, busiest first
    hard = benign[:HARD]
    easy = random.Random(7).sample(benign[HARD:], EASY)

    def incident_of(host: str) -> str | None:
        # The generator names each incident after its hosts, e.g. lateral_movement_ws017_dc01.
        return next((name for name in planted["incidents"] if host.replace("-", "") in name), None)

    rows = []
    for kind, group in (("malicious", malicious), ("hard", hard), ("easy", easy)):
        for agent, hour, *_ in group:
            alerts = con.execute(ALERTS_SQL, [agent, hour]).fetchall()
            rows.append(
                {
                    "id": f"{agent}@{hour:%Y-%m-%dT%H}",
                    "host": agent,
                    "hour": f"{hour:%Y-%m-%d %H:00}",
                    "label": "escalate" if kind == "malicious" else "close",
                    "kind": kind,
                    "incident": incident_of(agent) if kind == "malicious" else None,
                    "summary": summarise(alerts),
                }
            )
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"{len(malicious)} malicious, {len(hard)} hard benign, {len(easy)} easy benign -> {OUT.relative_to(ROOT)}")


def load() -> list[dict]:
    return [json.loads(line) for line in OUT.read_text().splitlines()]


if __name__ == "__main__":
    main()
