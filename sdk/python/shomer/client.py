"""
Shomer Python SDK (zero-dependency, stdlib only).

Every sensitive action your agent performs goes through Shomer first:

    sh = Shomer(agent_id="refunds-prod")
    r = sh.execute("issue_refund", {"order_id": "O-1", "amount_usd": 42}, estimated_cost_usd=0.15)
    if r["allowed"]:
        ... do the thing ...
        sh.complete(r["decision_id"], cost_usd=0.14, tokens=830)
"""

import json
import time
import urllib.error
import urllib.request


class ShomerError(RuntimeError):
    pass


class Shomer:
    def __init__(self, agent_id, base_url="http://localhost:8787", api_key=None, timeout=30):
        self.agent_id = agent_id
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # ---- low level ----
    def _req(self, path, payload=None, method=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise ShomerError("HTTP %s on %s: %s" % (e.code, path, body))

    # ---- agent-facing API ----
    def evaluate(self, tool, args=None, estimated_cost_usd=None, context=None):
        return self._req(
            "/v1/evaluate",
            {
                "agent_id": self.agent_id,
                "tool": tool,
                "args": args or {},
                "estimated_cost_usd": estimated_cost_usd,
                "context": context,
            },
        )

    def complete(self, decision_id, cost_usd=0.0, tokens=0, status="succeeded", result_summary=""):
        return self._req(
            "/v1/complete",
            {
                "decision_id": decision_id,
                "cost_usd": cost_usd,
                "tokens": tokens,
                "status": status,
                "result_summary": result_summary,
            },
        )

    # ---- human-in-the-loop ----
    def approval_status(self, approval_id):
        return self._req("/api/approvals/" + approval_id)

    def resolve_approval(self, approval_id, approved, by="sdk"):
        return self._req(
            "/api/approvals/%s/resolve" % approval_id,
            {"approved": bool(approved), "by": by},
        )

    def wait_for_approval(self, approval_id, timeout_s=120, poll_s=2.0):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            st = self.approval_status(approval_id).get("status")
            if st != "pending":
                return st
            time.sleep(poll_s)
        return "timeout"

    # ---- broker: the call goes THROUGH the control plane, which holds the credential ----
    def call(self, tool, args=None):
        """Execute a tool via the control plane broker (never bypasses policy,
        cost is metered server-side from real usage)."""
        return self._req(
            "/mcp/v1/tools/%s/call" % tool,
            {"agent_id": self.agent_id, "args": args or {}},
        )

    # ---- one-call guard ----
    def execute(self, tool, args=None, estimated_cost_usd=None,
                wait_for_approval_s=120, poll_s=2.0):
        """Evaluate -> (if required) wait for a human decision -> return the verdict.

        Returns a dict: {decision, allowed, reason, args, decision_id, approval_id?}
        On 'allow'/'sanitize' you still owe Shomer a `complete()` with the actual cost.
        """
        r = self.evaluate(tool, args, estimated_cost_usd)
        if r.get("decision") == "require_human":
            status = self.wait_for_approval(r["approval_id"], timeout_s=wait_for_approval_s, poll_s=poll_s)
            if status == "approved":
                r = dict(r)
                r["decision"] = "allow"
                r["allowed"] = True
                r["reason"] = "approved_by_human"
            elif status == "denied":
                r = dict(r)
                r["decision"] = "deny"
                r["allowed"] = False
                r["reason"] = "denied_by_human"
            elif status == "timeout":
                r = dict(r)
                r["decision"] = "deny"
                r["allowed"] = False
                r["reason"] = "approval_timeout"
        return r
