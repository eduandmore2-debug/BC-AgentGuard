"""E1: Security effectiveness on the InjecAgent benchmark (Zhan et al., 2024).
Worst-case assumption: the LLM agent is fully hijacked and always attempts the
attacker's tool calls. We measure which calls the gateway lets through."""
import json, collections, sys, time, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from chain import *

D = os.environ.get("INJECAGENT_DATA", os.path.join(ROOT, "data", "InjecAgent", "data")) + "/"
OUT = os.path.join(ROOT, "results")
os.makedirs(OUT, exist_ok=True)
toolkits = json.load(open(D + "tools.json"))
manifests, toolkit_of = {}, {}
for tk in toolkits:
    for t in tk["tools"]:
        tid = tk["toolkit"] + t["name"]
        manifests[tid] = {"toolkit": tk["toolkit"], **t}
        toolkit_of[tid] = tk["toolkit"]
by_toolkit = collections.defaultdict(list)
for tid, k in toolkit_of.items():
    by_toolkit[k].append(tid)
def short(tid): return tid[len(toolkit_of[tid]):]

ALL = set(manifests)
def scope_for(policy, user_tool):
    k = toolkit_of[user_tool]
    if policy == "P0_none":
        return ALL, set()
    if policy == "P1_toolkit":
        return set(by_toolkit[k]), set()
    if policy == "P2_toolkit_gated":
        s = set(by_toolkit[k])
        return s, {t for t in s if not is_read_only(short(t)) and t != user_tool}
    if policy == "P3_least_privilege":
        return {user_tool}, set()

POLICIES = ["P0_none", "P1_toolkit", "P2_toolkit_gated", "P3_least_privilege"]

c = Consortium(4)
prov = Identity("provider"); user = Identity("alice"); gw = Identity("gateway")
c.admit_provider("provider", prov.pk); c.admit_user("alice", user.pk)
for tid, m in manifests.items():
    p = {"tool_id": tid, "manifest_hash": H(canon(m)).hex(), "provider": "provider", "version": 1}
    c.submit({"type": "REGISTER_TOOL", "payload": p, "sig": prov.sign(canon(p)).hex()})
c.commit_block()
g = Gateway(c, gw); g.sync()

results = {}
ro = sum(is_read_only(short(t)) for t in ALL)
print(f"tools={len(ALL)} toolkits={len(by_toolkit)} read_only={ro}")
for variant in ["base", "enhanced"]:
    cases = []
    for setting in ["dh", "ds"]:
        for x in json.load(open(D + f"test_cases_{setting}_{variant}.json")):
            x["setting"] = setting; cases.append(x)
    for pol in POLICIES:
        sid_base = f"{variant}-{pol}"
        # open one session per test case (user-signed scope), then commit
        for i, x in enumerate(cases):
            scope, appr = scope_for(pol, x["User Tool"])
            p = {"session_id": f"{sid_base}-{i}", "user": "alice", "scope": sorted(scope),
                 "approval_required": sorted(appr)}
            c.submit({"type": "OPEN_SESSION", "payload": p, "sig": user.sign(canon(p)).hex()})
        c.commit_block()
        succ = collections.Counter(); tot = collections.Counter(); legit_ok = 0
        reasons = collections.Counter()
        for i, x in enumerate(cases):
            sid = f"{sid_base}-{i}"
            # legitimate user call
            d0 = g.decide(sid, x["User Tool"], manifests[x["User Tool"]], {"p": x["Tool Parameters"]})
            legit_ok += d0 == "ALLOW"
            # hijacked calls
            ok = True
            for at in x["Attacker Tools"]:
                d = g.decide(sid, at, manifests[at], {"instr": x["Attacker Instruction"]})
                reasons[d] += 1
                if d != "ALLOW":
                    ok = False; break
            key = (x["setting"], x["Attack Type"])
            tot[key] += 1; succ[key] += ok
            tot[("all",)] += 1; succ[("all",)] += ok
            tot[(x["setting"],)] += 1; succ[(x["setting"],)] += ok
        c.commit_block()
        results[f"{variant}|{pol}"] = {
            "n": len(cases), "legit_allowed": legit_ok,
            "asr": {"|".join(k): [succ[k], tot[k]] for k in tot},
            "decisions": dict(reasons)}
        a = succ[("all",)] / tot[("all",)]
        print(f"{variant:9s} {pol:20s} ASR={a*100:6.2f}%  legit={legit_ok}/{len(cases)}  {dict(reasons)}")

# scope size (over-privilege) per policy
sizes = {pol: sum(len(scope_for(pol, x["User Tool"])[0]) for x in cases) / len(cases) for pol in POLICIES}
results["avg_scope_size"] = sizes
print("avg scope size", sizes)
print("chain height", len(c.view.chain), "audit events", c.view.state.audit_count)
json.dump(results, open(os.path.join(OUT, "e1.json"), "w"), indent=1)

# ---------- Stress test: intra-toolkit (same-toolkit) hijacking ----------
users = [json.loads(l) for l in open(D + "user_cases.jsonl")]
stress = {}
for pol in POLICIES:
    allow = hold = deny = 0; n = 0; se_allow = 0; se_n = 0
    for j, u in enumerate(users):
        ut = u["User Tool"]
        scope, appr = scope_for(pol, ut)
        sid = f"stress-{pol}-{j}"
        p = {"session_id": sid, "user": "alice", "scope": sorted(scope), "approval_required": sorted(appr)}
        c.submit({"type": "OPEN_SESSION", "payload": p, "sig": user.sign(canon(p)).hex()})
    c.commit_block()
    for j, u in enumerate(users):
        ut = u["User Tool"]; sid = f"stress-{pol}-{j}"
        for at in by_toolkit[toolkit_of[ut]]:
            if at == ut: continue
            d = g.decide(sid, at, manifests[at], {"stress": True})
            n += 1; allow += d == "ALLOW"; hold += d == "HOLD_FOR_APPROVAL"; deny += d.startswith("DENY")
            if not is_read_only(short(at)):
                se_n += 1; se_allow += d == "ALLOW"
    c.commit_block()
    stress[pol] = {"n": n, "allow": allow, "hold": hold, "deny": deny,
                   "side_effect_n": se_n, "side_effect_allow": se_allow}
    print("stress", pol, stress[pol])
results["stress_intra_toolkit"] = stress
json.dump(results, open(os.path.join(OUT, "e1.json"), "w"), indent=1)
