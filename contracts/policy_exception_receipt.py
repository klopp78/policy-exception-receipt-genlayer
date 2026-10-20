# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""Policy-bound, one-time exception receipts for autonomous agents."""

from genlayer import *
import hashlib
import json
import typing


class PolicyExceptionReceipt(gl.Contract):
    """Creates source-bound exceptions that cannot be altered, replayed, or used after expiry."""

    exception_count: u64
    exception_ids: DynArray[str]
    exceptions: TreeMap[str, str]

    def __init__(self):
        self.exception_count = u64(0)

    @gl.public.view
    def get_exception(self, exception_id: str) -> str:
        return self.exceptions.get(exception_id, "")

    @gl.public.view
    def list_exception_ids(self) -> str:
        return _canonical_json([item for item in self.exception_ids])

    @gl.public.write
    def request_exception(
        self,
        policy_id: str,
        action: str,
        action_hash: str,
        max_amount: u64,
        expires_at: u64,
        evidence_urls: DynArray[str],
    ) -> str:
        normalized_policy = _text(policy_id, "policy_id", 3, 120)
        normalized_action = _text(action, "action", 20, 800)
        normalized_action_hash = _digest(action_hash, "action_hash")
        amount = int(max_amount)
        expiry = int(expires_at)
        if amount <= 0:
            raise Exception("max_amount_must_be_positive")
        if expiry <= _now():
            raise Exception("expiry_must_be_in_future")

        urls = _urls([item for item in evidence_urls])
        manifest = _manifest(urls)
        if len({item["host"] for item in manifest}) < 2:
            raise Exception("two_independent_hosts_required")

        request_hash = _sha256_parts([
            "policy_exception_receipt.v1",
            normalized_policy,
            normalized_action,
            normalized_action_hash,
            str(amount),
            str(expiry),
            _canonical_json(manifest),
        ])

        def leader_fn():
            return _assess(
                normalized_policy,
                normalized_action,
                normalized_action_hash,
                amount,
                expiry,
                urls,
                manifest,
                request_hash,
            )

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                proposed = _parse_result(leader_result.calldata)
                independent = _parse_result(_assess(
                    normalized_policy,
                    normalized_action,
                    normalized_action_hash,
                    amount,
                    expiry,
                    urls,
                    manifest,
                    request_hash,
                ))
            except Exception:
                return False
            return (
                proposed["decision"] == independent["decision"]
                and proposed["request_hash"] == independent["request_hash"]
                and proposed["snapshot_hashes"] == independent["snapshot_hashes"]
                and proposed["snapshot_bundle_hash"] == independent["snapshot_bundle_hash"]
                and proposed["evidence_hosts"] == independent["evidence_hosts"]
                and abs(proposed["confidence"] - independent["confidence"]) <= 12
            )

        result = _parse_result(gl.vm.run_nondet_unsafe(leader_fn, validator_fn))
        self.exception_count = u64(int(self.exception_count) + 1)
        sequence = int(self.exception_count)
        exception_id = "exc_" + _sha256_parts([request_hash, str(sequence)])[:20]
        record = {
            "schema_version": "policy_exception_receipt.v1",
            "exception_id": exception_id,
            "sequence": sequence,
            "requester": str(gl.message.sender_address).lower(),
            "policy_id": normalized_policy,
            "action": normalized_action,
            "action_hash": normalized_action_hash,
            "max_amount": amount,
            "expires_at": expiry,
            "source_manifest": manifest,
            "request_hash": request_hash,
            "decision": result["decision"],
            "confidence": result["confidence"],
            "rationale": result["rationale"],
            "evidence_hosts": result["evidence_hosts"],
            "snapshot_hashes": result["snapshot_hashes"],
            "snapshot_bundle_hash": result["snapshot_bundle_hash"],
            "used": False,
        }
        record["receipt_hash"] = _sha256(_canonical_json(record))
        self.exceptions[exception_id] = _canonical_json(record)
        self.exception_ids.append(exception_id)
        return exception_id

    @gl.public.write
    def consume_exception(self, exception_id: str, action_hash: str, amount: u64) -> str:
        record = _record(self.exceptions.get(exception_id, ""))
        if str(gl.message.sender_address).lower() != record["requester"]:
            raise Exception("only_requester_can_consume")
        if record["decision"] != "approve":
            raise Exception("exception_not_approved")
        if record["used"]:
            raise Exception("exception_already_used")
        if _now() > int(record["expires_at"]):
            raise Exception("exception_expired")
        if _digest(action_hash, "action_hash") != record["action_hash"]:
            raise Exception("action_hash_mismatch")
        if int(amount) <= 0 or int(amount) > int(record["max_amount"]):
            raise Exception("amount_exceeds_receipt_cap")

        record["used"] = True
        record["used_at"] = _now()
        record["used_amount"] = int(amount)
        record["consumption_hash"] = _sha256_parts([
            exception_id,
            record["action_hash"],
            str(record["used_amount"]),
            str(record["used_at"]),
        ])
        self.exceptions[exception_id] = _canonical_json(record)
        return record["consumption_hash"]


def _assess(policy_id, action, action_hash, amount, expiry, urls, manifest, request_hash) -> str:
    snapshots, hashes = [], []
    for index, url in enumerate(urls):
        try:
            text = gl.nondet.web.render(url, mode="text")[:9000]
            readable = len(text.strip()) >= 40
        except Exception:
            text, readable = "SOURCE_UNAVAILABLE", False
        snapshot_hash = _sha256(text)
        hashes.append(snapshot_hash)
        snapshots.append({
            "source_index": index + 1,
            "host": manifest[index]["host"],
            "readable": readable,
            "snapshot_hash": snapshot_hash,
            "text": text,
        })

    bundle_hash = _sha256_parts([request_hash, _canonical_json(hashes)])
    readable_hosts = sorted({item["host"] for item in snapshots if item["readable"]})
    if len(readable_hosts) < 2:
        return _canonical_json({
            "decision": "deny",
            "confidence": 100,
            "rationale": "At least two independent readable sources are required.",
            "evidence_hosts": readable_hosts,
            "snapshot_hashes": hashes,
            "snapshot_bundle_hash": bundle_hash,
            "request_hash": request_hash,
        })

    prompt = f"""
You are an exception-policy adjudicator. Decide whether a one-time exception should be approved.
Approve only if the independently rendered evidence directly supports the stated exception and its
scope is specific, bounded, and reversible. Deny when sources contradict it, are stale/ambiguous,
or do not justify an exception. Never invent authority from a source.

Policy identifier: {policy_id}
Requested action: {action}
Action commitment: {action_hash}
Maximum amount: {amount}
Expiry timestamp: {expiry}
Source provenance: {_canonical_json(manifest)}
Rendered evidence: {_canonical_json(snapshots)}

Return minified JSON only: decision (approve|deny), confidence (0-100), and rationale (1-420 chars).
"""
    raw = json.loads(gl.nondet.exec_prompt(prompt))
    decision = str(raw.get("decision", "")).lower()
    confidence = int(raw.get("confidence", -1))
    rationale = str(raw.get("rationale", "")).strip()[:420]
    if decision not in ("approve", "deny") or not 0 <= confidence <= 100 or not rationale:
        raise Exception("invalid_model_result")
    return _canonical_json({
        "decision": decision,
        "confidence": confidence,
        "rationale": rationale,
        "evidence_hosts": readable_hosts,
        "snapshot_hashes": hashes,
        "snapshot_bundle_hash": bundle_hash,
        "request_hash": request_hash,
    })


def _parse_result(raw: str) -> dict:
    item = json.loads(raw)
    if item.get("decision") not in ("approve", "deny"):
        raise Exception("invalid_decision")
    if not 0 <= int(item.get("confidence", -1)) <= 100:
        raise Exception("invalid_confidence")
    if not 0 < len(str(item.get("rationale", ""))) <= 420:
        raise Exception("invalid_rationale")
    hashes = item.get("snapshot_hashes", [])
    if not isinstance(hashes, list) or len(hashes) < 2 or any(not _is_digest(str(value)) for value in hashes):
        raise Exception("invalid_snapshot_hashes")
    for field in ("snapshot_bundle_hash", "request_hash"):
        if not _is_digest(str(item.get(field, ""))):
            raise Exception("invalid_commitment")
    item["confidence"] = int(item["confidence"])
    item["evidence_hosts"] = sorted([str(value) for value in item.get("evidence_hosts", [])])
    return item


def _record(raw: str) -> dict:
    if not raw:
        raise Exception("unknown_exception")
    return json.loads(raw)


def _urls(raw_urls: typing.Sequence[str]) -> typing.Sequence[str]:
    if len(raw_urls) < 2 or len(raw_urls) > 4:
        raise Exception("use_two_to_four_sources")
    urls, seen = [], set()
    for raw in raw_urls:
        url = str(raw).strip()
        key = url.rstrip("/").lower()
        if not url.startswith("https://") or len(url) > 600 or key in seen:
            raise Exception("invalid_or_duplicate_source_url")
        seen.add(key)
        urls.append(url)
    return urls


def _manifest(urls: typing.Sequence[str]) -> typing.Sequence[dict]:
    return [{"source_index": index + 1, "url": url, "host": _host(url), "url_hash": _sha256(url)} for index, url in enumerate(urls)]


def _host(url: str) -> str:
    host = url.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    if "." not in host or len(host) > 253:
        raise Exception("invalid_source_host")
    return host


def _text(raw: str, field: str, minimum: int, maximum: int) -> str:
    value = str(raw).strip()
    if len(value) < minimum or len(value) > maximum or "\n" in value or "\r" in value:
        raise Exception("invalid_" + field)
    return value


def _digest(raw: str, field: str) -> str:
    value = str(raw).strip().lower()
    if not _is_digest(value):
        raise Exception("invalid_" + field)
    return value


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_parts(parts: typing.Sequence[str]) -> str:
    return "".join(str(len(str(part))) + ":" + str(part) for part in parts)


def _sha256_parts(parts: typing.Sequence[str]) -> str:
    return _sha256(_canonical_parts(parts))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _now() -> int:
    return int(gl.block.timestamp)
