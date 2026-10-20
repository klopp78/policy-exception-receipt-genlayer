from pathlib import Path


source = Path(__file__).parents[1] / "contracts" / "policy_exception_receipt.py"
text = source.read_text(encoding="utf-8")

required = [
    "def request_exception(",
    "def consume_exception(",
    "gl.nondet.web.render",
    "gl.vm.run_nondet_unsafe",
    "def validator_fn",
    "hashlib.sha256",
    "exception_already_used",
    "action_hash_mismatch",
    "amount_exceeds_receipt_cap",
    "only_requester_can_consume",
]

missing = [needle for needle in required if needle not in text]
if missing:
    raise SystemExit("missing required contract safeguards: " + ", ".join(missing))

if "% 1000000007" in text:
    raise SystemExit("legacy non-cryptographic commitment detected")

print("PolicyExceptionReceipt contract checks passed")
