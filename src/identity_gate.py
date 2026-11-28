#!/usr/bin/env python3
#
# Copyright 2026 元极恒一
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-
"""identity_gate.py — 约束运行时·身份闸 v0.1（L1 身份，2026-11-28）

定位：对齐《元枢 Agent OS 能力对齐规范 v0.1》第 03/04 章——官方攻关清单
「智能体标识」项的运行时算子。约束线前五件管「行为怎么管」，本件管
「谁在发请求」：没有可信身份的调用方，进不了决策流。

核心概念：
- 注册即登记：agent_id + 口令指纹（盐化哈希）+ 权限清单，一次登记；
- 挑战-应答握手：服务端发一次性 nonce，调用方以「口令指纹 + nonce」
  的哈希应答——服务端无需保存口令原文即可验证；
- nonce 单次有效：重放同一应答直接拒绝（防重放攻击）；
- 权限即清单：动作必须出现在该身份的权限清单内，未登记身份、
  未授权动作一律拒绝（fail-closed）；
- 吊销即生效：吊销后该身份一切握手与授权立即拒绝；
- 事件入哈希链：注册、握手、授权、吊销全部入链，篡改可发现。

诚实边界：本件是单机信任模型——不防能同时改写内存与台账文件的本地
攻击者；口令指纹用快速哈希而非慢哈希，生产环境暴露在离线爆破风险下
时应换慢哈希或改用硬件凭据。

用法：
    from identity_gate import IdentityGate
    gate = IdentityGate()
    gate.register("agent-1", "secret-1", {"read", "write"})
    ch = gate.challenge("agent-1")                 # 一次性 nonce
    proof = gate.proof_of("secret-1", ch["nonce"]) # 调用方侧计算
    ok, why = gate.handshake("agent-1", ch["nonce"], proof)
    ok, why = gate.authorize("agent-1", "write")   # 权限校验

CLI 自检：
    identity_gate.py selftest
"""

import hashlib
import hmac
import json
import os
import secrets
import time


def _entry_hash(seq, ts, event, detail, prev):
    payload = json.dumps({"seq": seq, "ts": ts, "event": event,
                          "detail": detail, "prev": prev},
                         ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class IdentityGate:
    """身份闸：注册即登记、握手验真、权限即清单、吊销即生效。"""

    def __init__(self, chain_path=None):
        self.chain_path = chain_path
        self.entries = []
        self.agents = {}     # agent_id -> {"fp": hex, "perms": set, "revoked": bool}
        self._used_nonce = set()
        if chain_path and os.path.exists(chain_path):
            self._load_chain()

    # ---------- 哈希链 ----------

    def _append(self, event, detail):
        seq = len(self.entries) + 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S+08:00")
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        entry = {"seq": seq, "ts": ts, "event": event,
                 "detail": detail, "prev": prev,
                 "hash": _entry_hash(seq, ts, event, detail, prev)}
        self.entries.append(entry)
        self._flush()
        return entry

    def _flush(self):
        if not self.chain_path:
            return
        os.makedirs(os.path.dirname(self.chain_path) or ".", exist_ok=True)
        with open(self.chain_path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")

    def _load_chain(self):
        with open(self.chain_path, encoding="utf-8") as f:
            self.entries = [json.loads(line) for line in f if line.strip()]

    def verify_chain(self):
        prev = "GENESIS"
        for e in self.entries:
            expect = _entry_hash(e["seq"], e["ts"], e["event"], e["detail"], prev)
            if e["prev"] != prev or e["hash"] != expect:
                return False, {"broken_at_seq": e["seq"]}
            prev = e["hash"]
        return True, {"entries": len(self.entries)}

    # ---------- 注册与吊销 ----------

    @staticmethod
    def fingerprint(secret):
        salt = "ys-identity-v1"
        return hashlib.sha256((salt + secret).encode("utf-8")).hexdigest()

    @staticmethod
    def proof_of(secret, nonce):
        """调用方侧应答：以口令指纹 + nonce 计算证明，口令原文不出本机。"""
        return hashlib.sha256(
            (IdentityGate.fingerprint(secret) + nonce).encode("utf-8")).hexdigest()

    def register(self, agent_id, secret, perms):
        if agent_id in self.agents:
            return False, "already_registered"
        self.agents[agent_id] = {"fp": self.fingerprint(secret),
                                 "perms": set(perms), "revoked": False}
        self._append("register", {"agent": agent_id, "perms": sorted(perms)})
        return True, "registered"

    def revoke(self, agent_id):
        if agent_id not in self.agents:
            return False, "unknown_agent"
        self.agents[agent_id]["revoked"] = True
        self._append("revoke", {"agent": agent_id})
        return True, "revoked"

    # ---------- 握手 ----------

    def challenge(self, agent_id):
        """签发一次性 nonce；未登记或已吊销身份直接拒绝。"""
        agent = self.agents.get(agent_id)
        if agent is None or agent["revoked"]:
            return None
        nonce = secrets.token_hex(16)
        self._used_nonce.add(nonce)
        return {"agent_id": agent_id, "nonce": nonce}

    def handshake(self, agent_id, nonce, proof):
        """验真：身份有效 + nonce 未用过 + 证明匹配，三者缺一即拒绝。

        0.4.1 评审修正：证明用常数时间比较（hmac.compare_digest），
        消除理论时序侧信道。nonce 在验证明前消费——错误证明同样作废
        nonce，防在线爆破；代价是知道 nonce 的中间人可作废合法方一次
        握手（fail-closed 方向，不泄露任何凭据信息）。
        """
        agent = self.agents.get(agent_id)
        if agent is None:
            return False, "unknown_agent"
        if agent["revoked"]:
            return False, "revoked"
        if nonce not in self._used_nonce:
            return False, "bad_nonce"          # 从未签发或已消费
        self._used_nonce.discard(nonce)         # nonce 单次有效
        expect = hashlib.sha256(
            (agent["fp"] + nonce).encode("utf-8")).hexdigest()
        if not isinstance(proof, str) or not hmac.compare_digest(proof, expect):
            self._append("handshake_fail", {"agent": agent_id})
            return False, "proof_mismatch"
        self._append("handshake_ok", {"agent": agent_id})
        return True, "authenticated"

    # ---------- 授权 ----------

    def authorize(self, agent_id, action):
        """权限即清单：未登记、已吊销、动作不在清单内，一律拒绝。"""
        agent = self.agents.get(agent_id)
        if agent is None:
            return False, "unknown_agent"
        if agent["revoked"]:
            return False, "revoked"
        if action not in agent["perms"]:
            self._append("authorize_deny", {"agent": agent_id, "action": action})
            return False, "permission_denied"
        return True, "allowed"


# ---------- CLI 自检 ----------

def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # 1 正常握手通过
    g = IdentityGate()
    g.register("a1", "s1", {"read"})
    ch = g.challenge("a1")
    ok, why = g.handshake("a1", ch["nonce"], IdentityGate.proof_of("s1", ch["nonce"]))
    check("正常握手通过", ok and why == "authenticated")

    # 2 同一应答重放拒绝（nonce 单次有效）
    ok, why = g.handshake("a1", ch["nonce"], IdentityGate.proof_of("s1", ch["nonce"]))
    check("重放应答拒绝", (not ok) and why == "bad_nonce")

    # 3 错误证明拒绝
    g = IdentityGate()
    g.register("a2", "s2", {"read"})
    ch = g.challenge("a2")
    ok, why = g.handshake("a2", ch["nonce"], "0" * 64)
    check("错误证明拒绝", (not ok) and why == "proof_mismatch")

    # 4 未登记身份拒绝
    g = IdentityGate()
    ok, why = g.handshake("ghost", "n", "p")
    check("未登记身份拒绝", (not ok) and why == "unknown_agent")

    # 5 吊销即生效：已签发的挑战也作废
    g = IdentityGate()
    g.register("a3", "s3", {"read"})
    ch = g.challenge("a3")
    g.revoke("a3")
    ok, why = g.handshake("a3", ch["nonce"], IdentityGate.proof_of("s3", ch["nonce"]))
    check("吊销后握手拒绝", (not ok) and why == "revoked")

    # 6 权限即清单：未授权动作拒绝
    g = IdentityGate()
    g.register("a4", "s4", {"read"})
    ok, why = g.authorize("a4", "write")
    check("未授权动作拒绝", (not ok) and why == "permission_denied")
    ok, why = g.authorize("a4", "read")
    check("已授权动作放行", ok and why == "allowed")

    # 7 未登记身份授权拒绝（fail-closed）
    g = IdentityGate()
    ok, why = g.authorize("ghost", "read")
    check("未登记身份授权拒绝", (not ok) and why == "unknown_agent")

    # 8 吊销后授权拒绝
    g = IdentityGate()
    g.register("a5", "s5", {"read"})
    g.revoke("a5")
    ok, why = g.authorize("a5", "read")
    check("吊销后授权拒绝", (not ok) and why == "revoked")

    # 9 哈希链校验通过
    g = IdentityGate()
    g.register("a6", "s6", {"read"})
    ch = g.challenge("a6")
    g.handshake("a6", ch["nonce"], IdentityGate.proof_of("s6", ch["nonce"]))
    ok, detail = g.verify_chain()
    check("哈希链校验通过", ok and detail["entries"] == 2)

    # 10 篡改发现
    g.entries[0]["detail"]["agent"] = "tampered"
    ok, detail = g.verify_chain()
    check("篡改可发现", (not ok) and detail["broken_at_seq"] == 1)

    passed = sum(1 for _, c in results if c)
    for name, cond in results:
        print(("PASS" if cond else "FAIL") + "  " + name)
    print(f"--- selftest: {passed}/{len(results)} passed ---")
    return passed == len(results)


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
