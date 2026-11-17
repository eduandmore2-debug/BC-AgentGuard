"""E3: Performance and scalability of BC-AgentGuard."""
import json, sys, time, statistics as st, platform, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from chain import *

D = os.environ.get("INJECAGENT_DATA", os.path.join(ROOT, "data", "InjecAgent", "data")) + "/"
OUT = os.path.join(ROOT, "results")
os.makedirs(OUT, exist_ok=True)
toolkits = json.load(open(D + "tools.json"))
manifests = {tk["toolkit"] + t["name"]: {"toolkit": tk["toolkit"], **t} for tk in toolkits for t in tk["tools"]}
tids = list(manifests)

def cpu_name():
    try:
        return next((l.split(":")[1].strip() for l in open("/proc/cpuinfo") if "model name" in l), "?")
    except OSError:
        return platform.processor() or "?"

out = {"platform": {"python": platform.python_version(), "machine": platform.machine(),
                    "cpu": cpu_name(), "cores": os.cpu_count()}}

def pct(a, q): a = sorted(a); return a[min(len(a) - 1, int(len(a) * q))]

def setup(n):
    c = Consortium(n); prov = Identity("provider"); u = Identity("alice")
    c.admit_provider("provider", prov.pk); c.admit_user("alice", u.pk)
    for tid, m in manifests.items():
        p = {"tool_id": tid, "manifest_hash": H(canon(m)).hex(), "provider": "provider", "version": 1}
        c.submit({"type": "REGISTER_TOOL", "payload": p, "sig": prov.sign(canon(p)).hex()})
    p = {"session_id": "s", "user": "alice", "scope": tids[:10], "approval_required": []}
    c.submit({"type": "OPEN_SESSION", "payload": p, "sig": u.sign(canon(p)).hex()})
    c.commit_block()
    g = Gateway(c, Identity("gw")); g.sync()
    return c, g

# --- (a) per-call gateway overhead
c, g = setup(4)
lat_full, lat_nolog = [], []
for i in range(3000):
    tid = tids[i % 10]
    t0 = time.perf_counter_ns(); g.decide("s", tid, manifests[tid], {"i": i}); lat_full.append(time.perf_counter_ns() - t0)
c.pending.clear()
for i in range(3000):
    tid = tids[i % 10]; t0 = time.perf_counter_ns()
    sess = c.view.state.sessions["s"]; g.check_manifest(tid, manifests[tid]); _ = tid in sess["scope"]
    lat_nolog.append(time.perf_counter_ns() - t0)
out["gateway_us"] = {"decision_only": {"median": st.median(lat_nolog) / 1e3, "p95": pct(lat_nolog, .95) / 1e3},
                     "decision_plus_signed_audit": {"median": st.median(lat_full) / 1e3, "p95": pct(lat_full, .95) / 1e3}}
print("gateway", out["gateway_us"])

# --- (b) consensus: block latency & throughput vs validators and batch size
def audit_tx(gid, i):
    tid = tids[i % 10]
    ev = {"gw": gid.name, "session": "s", "tool": tid, "args_hash": H(str(i).encode()).hex(), "decision": "ALLOW", "t": time.time()}
    return {"type": "AUDIT", "payload": ev, "sig": gid.sign(canon(ev)).hex()}

out["consensus"] = []
for n in [4, 7, 10, 13, 16]:
    c, g = setup(n)
    for b in [50, 100, 250, 500, 1000]:
        runs = []
        for r in range(5):
            for i in range(b): c.submit(audit_tx(g.id, i))
            t0 = time.perf_counter(); blk = c.commit_block(); dt = time.perf_counter() - t0
            runs.append(dt)
        med = st.median(runs)
        row = {"N": n, "f": c.f, "batch": b, "commit_s_sequential": med,
               "commit_s_per_validator": med / n, "tps_sequential": b / med, "tps_parallel_est": b / (med / n),
               "block_bytes": blk.size_bytes()}
        out["consensus"].append(row)
        print(row)

# --- (c) Merkle inclusion proofs for third-party audit
out["merkle"] = []
for b in [100, 1000, 10000, 100000]:
    leaves = [H(str(i).encode()) for i in range(b)]
    t0 = time.perf_counter(); root, levels = merkle_root_and_levels(leaves); tb = time.perf_counter() - t0
    vt = []
    for k in range(0, b, max(1, b // 200)):
        pr = merkle_proof(levels, k); t1 = time.perf_counter_ns(); assert merkle_verify(leaves[k], pr, root); vt.append(time.perf_counter_ns() - t1)
    out["merkle"].append({"leaves": b, "build_ms": tb * 1e3, "proof_hashes": len(pr),
                          "proof_bytes": len(pr) * 33, "verify_us_median": st.median(vt) / 1e3})
    print(out["merkle"][-1])

# --- (d) storage per audit event
c, g = setup(4)
for i in range(1000): c.submit(audit_tx(g.id, i))
blk = c.commit_block()
out["storage"] = {"events": 1000, "block_bytes": blk.size_bytes(), "bytes_per_event": blk.size_bytes() / 1000}
print(out["storage"])

# --- (e) tamper evidence: modify one historical audit record
victim = c.view.chain[-1]
orig_root = victim.root
tampered = [canon(t) for t in victim.txs]; tampered[123] = tampered[123].replace(b"ALLOW", b"DENY_")
new_root, _ = merkle_root_and_levels(tampered)
out["tamper_detected"] = new_root != orig_root
print("tamper detected", out["tamper_detected"])
json.dump(out, open(os.path.join(OUT, "e3.json"), "w"), indent=1)
