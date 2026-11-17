# BC-AgentGuard

Reference implementation and experiment scripts for the paper:

> **BC-AgentGuard: Blockchain-Anchored Capability and Audit Framework for Securing LLM Agents**
> Amani Alqarni — Department of Computer Science, College of Engineering and Computer Science, Jazan University, Jazan, Saudi Arabia (ORCID: [0000-0003-3143-3215](https://orcid.org/0000-0003-3143-3215))

BC-AgentGuard places a reference-monitor gateway between an LLM agent and its tools. Tool manifests, user-signed session capability scopes, and every gated tool call are anchored in a permissioned (consortium) ledger with PBFT-style consensus, giving manifest integrity (against tool poisoning and rug-pull attacks), least-privilege enforcement against indirect prompt injection, and a tamper-evident audit trail.

## Repository layout

```
src/chain.py                    Prototype: ECDSA P-256 identities, Merkle trees, PBFT-style
                                consortium ledger, chaincode (ToolRegistry, SessionPolicy,
                                AuditLog) and the gateway reference monitor
experiments/exp1_security.py    E1 - attack success rate on the InjecAgent benchmark
                                under four capability policies (P0-P3) + intra-toolkit stress test
experiments/exp2_poisoning.py   E2 - tool-poisoning / rug-pull detection with ledger-anchored
                                canonical manifest hashes
experiments/exp3_performance.py E3 - gateway overhead, consensus latency/throughput (N = 4..16),
                                Merkle proof cost, storage per audit event, tamper evidence
results/e1.json, e2.json, e3.json  Raw outputs reported in the paper
```

## Requirements

- Python 3.10+ (results were produced with Python 3.13)
- `cryptography` (see `requirements.txt`)

```bash
pip install -r requirements.txt
```

## Data

The experiments use the public **InjecAgent** benchmark (Zhan et al., 2024, *Findings of ACL 2024*), available at <https://github.com/uiuc-kang-lab/InjecAgent>. No human-subject data are used.

```bash
git clone https://github.com/uiuc-kang-lab/InjecAgent data/InjecAgent
```

The scripts look for `data/InjecAgent/data/` by default; set the `INJECAGENT_DATA` environment variable to use another location.

## Running

```bash
python experiments/exp1_security.py     # -> results/e1.json
python experiments/exp2_poisoning.py    # -> results/e2.json
python experiments/exp3_performance.py  # -> results/e3.json
```

Security results (E1, E2) are deterministic. Timing results (E3) depend on hardware; the reported numbers were measured on a 2-core Intel Xeon @ 2.30 GHz (x86_64). Consensus is simulated in a single process, so `tps_parallel_est` is an estimate that assumes validators run on separate machines.

## Citation

If you use this code, please cite the paper (citation details will be added after publication).

## License

MIT — see [LICENSE](LICENSE).
