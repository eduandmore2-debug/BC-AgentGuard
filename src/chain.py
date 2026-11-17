"""BC-AgentGuard prototype: permissioned blockchain layer.

Pure-Python consortium ledger:
  * ECDSA P-256 signatures (cryptography library), SHA-256 hashing
  * Merkle trees with inclusion proofs
  * PBFT-style three-phase commit (pre-prepare / prepare / commit) among N validators
  * Deterministic "chaincode" state machine with three contracts:
      ToolRegistry  - signed tool-manifest hashes (anti tool-poisoning / rug-pull)
      SessionPolicy - user-signed capability scope per agent session
      AuditLog      - append-only record of every gated tool call
"""
import hashlib, json, time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon(obj) -> bytes:
    """Canonical JSON encoding (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

class Identity:
    def __init__(self, name):
        self.name = name
        self.sk = ec.generate_private_key(ec.SECP256R1())
        self.pk = self.sk.public_key()
        self.pk_bytes = self.pk.public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.CompressedPoint)
    def sign(self, msg: bytes) -> bytes:
        return self.sk.sign(msg, ec.ECDSA(hashes.SHA256()))

def verify(pk, sig: bytes, msg: bytes) -> bool:
    try:
        pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# ---------------- Merkle tree ----------------
def merkle_root_and_levels(leaves):
    if not leaves:
        return H(b""), [[H(b"")]]
    level = [H(b"\x00" + l) for l in leaves]          # domain-separated leaf hashing
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [H(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return level[0], levels

def merkle_proof(levels, idx):
    proof = []
    for level in levels[:-1]:
        lv = level + [level[-1]] if len(level) % 2 else level
        sib = idx ^ 1
        proof.append((lv[sib], sib < idx))
        idx //= 2
    return proof

def merkle_verify(leaf, proof, root):
    h = H(b"\x00" + leaf)
    for sib, sib_is_left in proof:
        h = H(b"\x01" + sib + h) if sib_is_left else H(b"\x01" + h + sib)
    return h == root

# ---------------- Chaincode (contracts) ----------------
class StateMachine:
    def __init__(self):
        self.tools = {}       # tool_id -> {"hash", "provider", "version"}
        self.providers = {}   # provider name -> public key (consortium-admitted)
        self.sessions = {}    # session_id -> {"user", "scope", "approval_required"}
        self.users = {}       # user name -> public key
        self.gateways = {}    # gateway name -> public key
        self.audit_count = 0

    def apply(self, tx):
        t = tx["type"]; p = tx["payload"]
        if t == "REGISTER_TOOL":
            pk = self.providers[p["provider"]]
            if not verify(pk, bytes.fromhex(tx["sig"]), canon(p)):
                return False
            self.tools[p["tool_id"]] = {"hash": p["manifest_hash"], "provider": p["provider"],
                                        "version": p["version"]}
            return True
        if t == "OPEN_SESSION":
            pk = self.users[p["user"]]
            if not verify(pk, bytes.fromhex(tx["sig"]), canon(p)):
                return False
            self.sessions[p["session_id"]] = {"user": p["user"], "scope": set(p["scope"]),
                                              "approval_required": set(p["approval_required"])}
            return True
        if t == "AUDIT":
            pk = self.gateways.get(p["gw"])
            if pk is None or not verify(pk, bytes.fromhex(tx["sig"]), canon(p)):
                return False
            self.audit_count += 1
            return True
        return False

# ---------------- Ledger + PBFT-style consensus ----------------
class Block:
    def __init__(self, height, prev_hash, txs, proposer):
        self.height, self.prev_hash, self.txs, self.proposer = height, prev_hash, txs, proposer
        self.leaves = [canon(tx) for tx in txs]
        self.root, self.levels = merkle_root_and_levels(self.leaves)
        self.ts = time.time()
        self.header = canon({"h": height, "prev": prev_hash.hex(), "root": self.root.hex(),
                             "ts": self.ts, "proposer": proposer})
        self.hash = H(self.header)
        self.commit_sigs = {}

    def size_bytes(self):
        return len(self.header) + sum(len(l) for l in self.leaves) + \
               sum(len(s) for s in self.commit_sigs.values())

class Validator:
    def __init__(self, name):
        self.id = Identity(name)
        self.chain = []
        self.state = StateMachine()

class Consortium:
    """N validators, tolerates f = floor((N-1)/3) Byzantine faults."""
    def __init__(self, n):
        self.validators = [Validator(f"v{i}") for i in range(n)]
        self.n = n
        self.f = (n - 1) // 3
        self.quorum = 2 * self.f + 1
        self.pending = []
        self.stats = {"sign_ops": 0, "verify_ops": 0}

    @property
    def view(self):
        return self.validators[0]

    def admit_provider(self, name, pk):
        for v in self.validators: v.state.providers[name] = pk

    def admit_user(self, name, pk):
        for v in self.validators: v.state.users[name] = pk

    def admit_gateway(self, name, pk):
        for v in self.validators: v.state.gateways[name] = pk

    def submit(self, tx):
        self.pending.append(tx)

    def commit_block(self, max_txs=None):
        txs = self.pending[:max_txs] if max_txs else self.pending
        self.pending = self.pending[len(txs):]
        leader = self.validators[len(self.view.chain) % self.n]
        prev = self.view.chain[-1].hash if self.view.chain else b"\x00" * 32
        blk = Block(len(self.view.chain), prev, txs, leader.id.name)
        # Phase 1: pre-prepare (leader signs block hash)
        pp = leader.id.sign(b"PP" + blk.hash); self.stats["sign_ops"] += 1
        # Phase 2: prepare - each replica verifies leader sig + re-derives Merkle root, signs prepare
        prepares = []
        for v in self.validators:
            assert verify(leader.id.pk, pp, b"PP" + blk.hash); self.stats["verify_ops"] += 1
            root, _ = merkle_root_and_levels([canon(t) for t in txs])
            assert root == blk.root
            prepares.append((v, v.id.sign(b"PR" + blk.hash))); self.stats["sign_ops"] += 1
        # each replica verifies a quorum of prepares, then signs commit
        commits = []
        for v in self.validators:
            ok = 0
            for (u, s) in prepares[:self.quorum]:
                ok += verify(u.id.pk, s, b"PR" + blk.hash); self.stats["verify_ops"] += 1
            assert ok >= self.quorum
            commits.append((v, v.id.sign(b"CM" + blk.hash))); self.stats["sign_ops"] += 1
        # each replica verifies a quorum of commits, executes chaincode, appends block
        for v in self.validators:
            ok = 0
            for (u, s) in commits[:self.quorum]:
                ok += verify(u.id.pk, s, b"CM" + blk.hash); self.stats["verify_ops"] += 1
            assert ok >= self.quorum
            for tx in txs:
                v.state.apply(tx)
            v.chain.append(blk)
        blk.commit_sigs = {u.id.name: s for (u, s) in commits[:self.quorum]}
        return blk

# ---------------- Gateway (reference monitor) ----------------
READ_VERBS = ("Get", "Search", "Read", "List", "View", "Retrieve", "Check", "Find",
              "Query", "Fetch", "Lookup", "Show", "Download", "Analyze", "Track", "Browse")

def is_read_only(tool_name):
    return tool_name.startswith(READ_VERBS)

class Gateway:
    """Off-chain enforcement point between the LLM agent and its tools.
    Decisions are made against a locally cached, ledger-verified view of the state."""
    def __init__(self, consortium, identity):
        self.c = consortium
        self.id = identity
        self.cache_tools = {}   # tool_id -> manifest hash (synced from ledger)
        consortium.admit_gateway(identity.name, identity.pk)

    def sync(self):
        self.cache_tools = {k: v["hash"] for k, v in self.c.view.state.tools.items()}

    def check_manifest(self, tool_id, manifest):
        h = H(canon(manifest)).hex()
        return self.cache_tools.get(tool_id) == h

    def decide(self, session_id, tool_id, manifest, args, approved=False):
        sess = self.c.view.state.sessions.get(session_id)
        if sess is None:
            decision = "DENY_NO_SESSION"
        elif not self.check_manifest(tool_id, manifest):
            decision = "DENY_MANIFEST_MISMATCH"
        elif tool_id not in sess["scope"]:
            decision = "DENY_OUT_OF_SCOPE"
        elif tool_id in sess["approval_required"] and not approved:
            decision = "HOLD_FOR_APPROVAL"
        else:
            decision = "ALLOW"
        ev = {"gw": self.id.name, "session": session_id, "tool": tool_id, "args_hash": H(canon(args)).hex(),
              "decision": decision, "t": time.time()}
        tx = {"type": "AUDIT", "payload": ev}
        tx["sig"] = self.id.sign(canon(ev)).hex()
        self.c.submit(tx)
        return decision
