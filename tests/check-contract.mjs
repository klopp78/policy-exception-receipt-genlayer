import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../contracts/policy_exception_receipt.py", import.meta.url), "utf8");
const required = [
  "def request_exception(",
  "def consume_exception(",
  "gl.nondet.web.render",
  "gl.vm.run_nondet_unsafe",
  "def validator_fn",
  "hashlib.sha256",
  "exception_already_used",
  "action_hash_mismatch",
  "_canonical_action",
  "_registrable_domain",
  "two_independent_registrable_domains_required",
  "amount_exceeds_receipt_cap",
  "only_requester_can_consume",
];

const missing = required.filter((needle) => !source.includes(needle));
if (missing.length) throw new Error(`Missing safeguards: ${missing.join(", ")}`);
if (source.includes("% 1000000007")) throw new Error("Legacy non-cryptographic commitment detected");
if (source.includes("two_independent_hosts_required")) throw new Error("Host-only source diversity check detected");
console.log("PolicyExceptionReceipt contract checks passed");
