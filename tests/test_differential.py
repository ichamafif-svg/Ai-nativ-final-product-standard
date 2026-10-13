"""The two judges, differentially (§6.4): random admitted histories, then faults injected into the kernel's deltas.

Every entry the kernel admits must pass the independent checker unchanged; every delta altered after admission must be
refused by it. Seeded and bounded so the suite stays deterministic; STANDARD_DIFFERENTIAL=N runs N histories.
"""
import copy
import os
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fixture import HOUR, Ledger  # noqa: E402
from kernel import Refused  # noqa: E402
from bt.checker import Disagreement  # noqa: E402

RUNS = int(os.environ.get("STANDARD_DIFFERENTIAL", "12"))
STEPS = 60
SHA = ["a" * 40, "b" * 40]
HUMANS = ("h1", "h2")


def setup(L):
    L.checkpoint()
    caps = {"scanner": L.grant("scanner", ["observe", "certify:real"], ["repo:*", "run:*", "build:*"]),
            "oracle": L.grant("oracle", ["reconcile", "evidence", "certify:real"], ["repo:*", "run:*"]),
            "human": L.grant("h1", ["observe", "certify:real"], ["repo:*", "run:*"]),
            "agent": L.grant("agent", ["effect:remediate", "effect:deploy"], ["repo:*", "run:*"]),
            "plain": L.grant("agent", ["effect:inventory-refresh"], ["repo:*"], [], budget={"count": 3, "window": HOUR})}
    return caps


def proposal(rng, L, caps):
    """One random, plausible entry: (kind, author, signers, fields). Many are refused; that is part of the test."""
    s = L.state
    pick = rng.choice
    at = s["last_at"] + pick([0, 1, 1, 1, 50, 1_000, 400_000])
    intents = sorted(s["intents"])
    tokens = sorted(s["tokens"])
    base, head = (SHA[0], SHA[1]) if rng.random() < 0.85 else (pick(SHA), pick(SHA))   # facts meet on one move
    res = f"repo:code:sast/{base}/{head}"
    choice = rng.choices(range(13), weights=[2, 1, 1, 1, 12, 3, 5, 5, 5, 4, 2, 2, 1])[0]
    if choice == 0:
        return "checkpoint", "w1", None, {"at": at + pick([0, 60_000, HOUR]), "size": s["size"], "head": s["head"]}
    if choice == 1:
        return "freeze", pick(HUMANS + ("agent",)), None, {"at": at, "scope": pick(["repo:*", "run:*", "x:*", res])}
    if choice == 2 and s["frozen"]:
        return "unfreeze", pick(HUMANS + ("agent",)), None, {"at": at, "scope": pick(sorted(s["frozen"]))}
    if choice == 3:
        from fixture import client_law
        client = pick([client_law(), client_law(routes={"remediate": ["reproduced"]}),
                       client_law(settings={"burn_fast": "20"}), client_law(settings={"burn_fast": "1"})])
        return "law", pick(("h1", "agent")), None, {"at": at, "client": client}
    if choice == 4:
        from standard.floors import INSTRUMENTS
        good = {"tests": "green", "reproduced": "yes", "regressions": "none", "scoped": "yes", "candidate": "yes",
                "window": "open", "budget_pct": "50"}
        prop = pick(sorted(good))
        method, coverage, _ = INSTRUMENTS[prop]
        resource = res if prop not in ("candidate", "window", "budget_pct") else f"run:release:all/{base}/{head}"
        return "measurement", "scanner" if rng.random() < 0.9 else "oracle", None, {
            "at": at, "under": caps["scanner"], "resource": resource, "property": prop,
            "status": good[prop] if rng.random() < 0.8 else "red", "level": "real", "method": method, "coverage": coverage,
            "measured_at": at - pick([0, 0, 5, 10 ** 9]), "artifact": "sha256:" + "0" * 64}
    if choice == 5:
        author = pick(("h1", "scanner", "agent"))
        cap = caps["human"] if author == "h1" else caps["scanner"]
        return "observation", author, None, {"at": at, "under": cap, "resource": res, "property": "decision",
                                             "status": pick(["approve", "reject"]), "level": "real"}
    if choice == 6:
        route = pick(["agent", "plain", "deploy"])
        if route == "plain":
            return "intent", "agent", None, {"at": at, "under": caps["plain"], "op": "inventory-refresh",
                                             "args": {"scope": pick(["all", "x"])}}
        if route == "deploy":
            return "intent", "agent", None, {"at": at, "under": caps["agent"], "op": "deploy",
                                             "args": {"from": base, "to": head}}
        fields = {"at": at, "under": caps["agent"], "op": "remediate",
                  "args": {"area": "code", "item": "sast", "base": base, "head": head}}
        if intents and rng.random() < 0.3:
            fields["retry_of"] = pick(intents)
        return "intent", "agent", None, fields
    if choice == 7 and intents:
        it = s["intents"][pick(intents)]
        from kernel import digest
        signers = ["guard"]
        return "token", "guard", signers, {"at": at, "intent": it["id"], "args_digest": digest(it["args"])}
    if choice == 8 and tokens:
        return "reservation", "guard", None, {"at": at, "token": pick(tokens)}
    if choice == 9 and tokens:
        return "execution", "guard", None, {"at": at + pick([0, 400_000]), "token": pick(tokens),
                                            "result": pick(["ok", "failed", "unknown"])}
    if choice == 10 and intents:
        return "reconciliation", "oracle", None, {"at": at + pick([0, 400_000]), "under": caps["oracle"],
                                                  "intent": pick(intents), "result": pick(["applied", "not_applied"])}
    if choice == 11 and intents:
        it = s["intents"][pick(intents)]
        return "evidence", "oracle", None, {"at": at, "under": caps["oracle"], "resource": it["resource"],
                                            "subject": it["id"], "level": "real"}
    if choice == 12 and s["grants"] and rng.random() < 0.2:
        return "revoke", pick(("h2", "agent")), None, {"at": at, "grant": pick(sorted(s["grants"]))}
    return "checkpoint", "w1", None, {"at": at, "size": s["size"], "head": s["head"]}


def mutations(delta, rng):
    """Faults injected into an admitted delta: drop an operation, change a value, add an unexpected write."""
    ops = [op for op in delta if op[:2] not in (("put", "statements"),)]
    out = []
    if ops:
        drop = rng.choice(ops)
        out.append(("drop", [op for op in delta if op is not drop]))
        victim = rng.choice([op for op in delta if len(op) >= 3])
        changed = victim[:-1] + ({"forged": True},) if victim[0] in ("put", "push") or victim[1] in (
            "root", "law") else victim[:-1] + ("forged",)
        out.append(("change", [changed if op is victim else op for op in delta]))
    out.append(("add", [*delta, ("put", "grants", "forged-grant", {"holder": "agent"})]))
    return out


class Differential(unittest.TestCase):
    def test_both_judges_agree_on_random_histories_and_faults_are_caught(self):
        admitted, refused, missed = 0, 0, []
        for run in range(RUNS):
            rng = random.Random(1000 + run)
            L = Ledger()
            caps = setup(L)
            for _ in range(STEPS):
                kind, author, signers, fields = proposal(rng, L, caps)
                L.n += 1
                body = {"id": f"{kind}-{run}-{L.n}", "author": author, **fields}
                entry = L.entry(kind, body, signers or [author])
                try:
                    record, delta = L.kernel.decide(L.state, entry)
                except Refused:
                    refused += 1
                    continue
                law = L.kernel.law_by_digest(record["law"])
                L.checker.check(L.state, record, copy.deepcopy(delta), entry, law.raw, law.digest)   # must agree
                for name, forged in mutations(delta, rng):
                    try:
                        L.checker.check(L.state, record, copy.deepcopy(forged), entry, law.raw, law.digest)
                        missed.append((kind, name))
                    except Disagreement:
                        pass
                from kernel import apply
                apply(L.state, delta)
                L.entries.append(entry)
                admitted += 1
        self.assertGreater(admitted, RUNS * 5)
        self.assertGreater(refused, 0)
        self.assertEqual(missed, [], f"faults the independent checker let through: {sorted(set(missed))}")


if __name__ == "__main__":
    unittest.main()
