"""
Shomer demo: "Customer Refunds Agent" hits every control type.

Run:
    1) start the control plane:  npm run start   (in the shomer/ folder)
    2) open the dashboard:       http://localhost:8787
    3) run this agent:           python demo/refunds_agent.py

When the agent asks for human approval, approve it in the dashboard
(or type 'auto' in the console to let the demo operator approve it).

Expected storyline:
  allow -> allow -> sanitize(PII) -> require_human($320) -> deny($5000 hard cap)
  -> runaway loop blocked -> budget exhausted -> even cheap calls blocked
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdk", "python")
)

from shomer import Shomer  # noqa: E402

COSTS = {"lookup_order": 0.02, "issue_refund": 0.15, "notify_customer": 0.03}

def _dev_key():
    """The dev key is printed once on first boot and saved to data/DEV_KEY.txt."""
    import io
    try:
        with io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "DEV_KEY.txt")) as f:
            return f.read().strip()
    except Exception:
        return None


sh = Shomer(
    agent_id="refunds-prod",
    base_url=os.environ.get("SHOMER_URL", "http://localhost:8787"),
    api_key=os.environ.get("SHOMER_API_KEY") or _dev_key(),
)

summary = {"allow": 0, "sanitize": 0, "require_human": 0, "deny": 0}


def run(tool, args, note=""):
    r = sh.execute(tool, args, estimated_cost_usd=COSTS.get(tool, 0.02), wait_for_approval_s=180)
    summary[r["decision"]] = summary.get(r["decision"], 0) + 1
    print("\n> %s  args=%s" % (tool, args))
    if note:
        print("  scenario: %s" % note)
    print(
        "  verdict : %-13s allowed=%-5s reason=%s  budget_left=$%s"
        % (r["decision"], r["allowed"], r.get("reason"), r.get("budget_remaining_usd"))
    )
    if r.get("redactions"):
        print("  redactions: %s  -> args after sanitize: %s" % (r["redactions"], r["args"]))
    if r["allowed"]:
        sh.complete(r["decision_id"], cost_usd=COSTS.get(tool, 0.02), tokens=250, result_summary="ok")
    return r


print("=" * 64)
print("SHOMER DEMO - Customer Refunds Agent (budget: $1.00/day)")
print("=" * 64)

# 1) a normal small refund, fully autonomous
run("lookup_order", {"order_id": "O-1001"}, "normal ticket")
run("issue_refund", {"order_id": "O-1001", "amount_usd": 18}, "small refund, under threshold")
run("notify_customer", {"order_id": "O-1001", "customer_email": "alice@example.com"},
    "PII in args -> should be REDACTED, then allowed")

# 2) a large refund -> human approval required
d = sh.evaluate("issue_refund", {"order_id": "O-1002", "amount_usd": 320}, estimated_cost_usd=0.15)
summary[d["decision"]] = summary.get(d["decision"], 0) + 1
print("\n> issue_refund  args={'order_id': 'O-1002', 'amount_usd': 320}")
print("  scenario: $320 refund -> requires human approval")
print("  verdict : %-13s allowed=%-5s reason=%s" % (d["decision"], d["allowed"], d.get("reason")))
mode = input("  [human-in-the-loop] approve in the dashboard and press Enter,\n"
             "  or type 'auto' to let the demo operator approve: ").strip().lower()
if mode == "auto":
    sh.resolve_approval(d["approval_id"], approved=True, by="demo_operator")
    print("  demo_operator approved via API")
status = sh.wait_for_approval(d["approval_id"], timeout_s=180)
print("  approval status: %s" % status)
if status == "approved":
    sh.complete(d["decision_id"], cost_usd=0.15, tokens=250, result_summary="refund issued after approval")
    summary["allow"] += 1
    summary["require_human"] -= 1
run("notify_customer", {"order_id": "O-1002"}, "notify customer after approved refund")

# 3) absurd refund -> hard cap denial
run("issue_refund", {"order_id": "O-1003", "amount_usd": 5000}, "way above the $1000 hard cap -> DENIED")

# 4) runaway loop: same call repeated -> circuit breaker
for i in range(4):
    run("issue_refund", {"order_id": "O-1004", "amount_usd": 60},
        "attempt %s/4 of the SAME call -> runaway loop protection" % (i + 1))

# 5) grind the budget down until everything is blocked
#    (unique args per burst so runaway-loop protection does not kick in - this is a
#     spend-grinding scenario, the loop-protection scenario was step 4)
for i in range(20):
    run("notify_customer", {"order_id": "O-1005", "seq": i}, "bulk notifications (burst %s)" % (i + 1))
run("issue_refund", {"order_id": "O-1007", "amount_usd": 40}, "budget almost gone -> DENIED")
run("notify_customer", {"order_id": "O-1008"}, "even a cheap call is blocked once the budget is gone")

print("\n" + "=" * 64)
print("SUMMARY: %s" % summary)
print("Open http://localhost:8787 to see the full audit trail,")
print("then try GET http://localhost:8787/v1/ledger/verify to check the evidence chain.")
print("=" * 64)
