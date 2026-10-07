"""Static, offline HTML engineering report built from validated lab evidence.

The page is the packaged artifact-kit shell (shell.html) with one escaped body fragment injected
at a marker. Every value taken from evidence is control-character stripped, length bounded,
scanned for secret-like material (PEM armour, key labels, TLS key-log markers, long base64 runs)
and HTML escaped. No remote asset, script or font is referenced; the shell carries a strict CSP
that pins the kit script by hash.
"""

from __future__ import annotations

import base64
import hashlib
import html
import os
import re
import stat
import tempfile
from collections import Counter
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Any

from cryptoagility import benchmark, migration, policy, tls
from cryptoagility.reporting.evidence import (
    EVIDENCE_FILES,
    INVALID,
    LOADED,
    MISSING,
    OPTIONAL_EVIDENCE,
    Evidence,
    EvidenceError,
    load_evidence,
)

SHELL_RESOURCE = "shell.html"
BODY_MARKER = "<!--CRYPTOAGILITY_REPORT_BODY-->"
MAX_REPORT_BYTES = 16 * 1024 * 1024

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]")
_SECRET = re.compile(
    r"-----\s*(?:BEGIN|END)|PRIVATE KEY|Master-Key|CLIENT_RANDOM|"
    r"_TRAFFIC_SECRET|\bPSK\b|[A-Za-z0-9+/]{120,}={0,2}"
)
_SLUG = re.compile(r"[^a-z0-9_-]+")
REDACTED = "[redacted: secret-like content]"

OUTCOME_STATE = {
    "APPROVED": "done",
    "ACCEPTABLE_FOR_NOW": "active",
    "EXPERIMENTAL": "active",
    "MIGRATION_REQUIRED": "at-risk",
    "DEPRECATED": "blocked",
    "UNSUPPORTED": "blocked",
}
READINESS_STATE = {
    "READY": "done",
    "PARTIALLY_READY": "at-risk",
    "UNKNOWN": "planned",
    "BLOCKED": "blocked",
}
PRIORITY_STATE = {
    "IMMEDIATE": "blocked",
    "SHORT_TERM": "at-risk",
    "MEDIUM_TERM": "active",
    "MONITOR": "planned",
    "UNKNOWN": "planned",
}
MATRIX_STATE = {
    tls.SUCCESS: "done",
    tls.FAIL_NEGOTIATION: "blocked",
    tls.FAIL_CERTIFICATE: "blocked",
    tls.FAIL_PROFILE_MISMATCH: "blocked",
    tls.UNSUPPORTED: "planned",
    tls.ERROR: "blocked",
}
BENCH_STATE = {"SUCCESS": "done", "UNSUPPORTED": "planned", "ERROR": "blocked"}
OP_ORDER = ("keygen", "sign", "verify", "encapsulate", "decapsulate", "handshake", "process")

LIMITATIONS = (
    "Everything in this report comes from a local lab on a single host with native "
    "project-local OpenSSL; it is not production, network, hardware-module or FIPS 140 "
    "evidence and does not certify any deployment.",
    "ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are standardized algorithms. "
    "TLS 1.3 hybrid/PQC group code points and post-quantum X.509/TLS signature integrations "
    "are laboratory experiments whose interoperability can change.",
    "TLS identities are synthetic and disposable; handshakes run over loopback, so latency "
    "and byte counts exclude real network paths, middleboxes and TCP/IP framing.",
    "Timings are whole OpenSSL CLI processes, sampled sequentially on a shared host without "
    "CPU pinning; they describe this environment only and do not rank algorithms in general.",
    "Inventory coverage is limited to the files that were scanned; discovery errors and "
    "unrecognised assets mean the inventory is incomplete, not that nothing else exists.",
    "Policy outcomes and priorities follow the selected lab policy file; a different policy "
    "produces different findings. Priorities are planning inputs, not risk ratings.",
    "The CBOM is a project-specific format (cryptoagility-lab-cbom), not CycloneDX.",
)


class ReportError(RuntimeError):
    """The report could not be produced (bad results directory, output path or shell)."""


# --------------------------------------------------------------------------- text safety


class _Text:
    def __init__(self) -> None:
        self.redactions = 0

    def raw(self, value: Any, limit: int = 240) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            text = "yes" if value else "no"
        elif isinstance(value, int | float):
            text = format(value, ",") if isinstance(value, int) else f"{value:,.3f}"
        elif isinstance(value, str):
            text = value
        else:
            return ""
        text = " ".join(_CONTROL.sub(" ", text).split())
        if _SECRET.search(text):
            self.redactions += 1
            return REDACTED
        if len(text) > limit:
            text = text[: limit - 1].rstrip() + "\u2026"
        return text

    def __call__(self, value: Any, limit: int = 240, missing: str = "\u2014") -> str:
        text = self.raw(value, limit)
        return html.escape(text if text else missing, quote=True)


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _slug(value: Any) -> str:
    slug = _SLUG.sub("-", str(value).lower()).strip("-")[:40]
    return slug or "other"


def _status(label: str, state: str) -> str:
    return f'<span class="a-status" data-state="{_esc(state)}">{_esc(label)}</span>'


def _ms(value: Any) -> str:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return f"{value:,.3f}"
    return "\u2014"


def _bytes(value: Any) -> tuple[str, str]:
    """(display text, chart value) for an integer or {min, max} size."""
    if isinstance(value, dict):
        low, high = value.get("min"), value.get("max")
        if isinstance(low, int) and isinstance(high, int):
            text = f"{high:,}" if low == high else f"{low:,}\u2013{high:,}"
            return text, str(high)
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}", str(value)
    return "\u2014", ""


def _scalar(value: Any) -> Any:
    return value if isinstance(value, str | int | float | bool) else None


def _section(ident: str, title: str, body: str, lead: str = "") -> str:
    prose = f'<div class="a-prose"><p>{lead}</p></div>' if lead else ""
    return (
        f'<section class="a-section" id="{ident}" aria-labelledby="{ident}-title">'
        f'<h2 class="a-section__title" id="{ident}-title">{_esc(title)}</h2>'
        f"{prose}{body}</section>"
    )


def _panel(title: str, body: str, attrs: str = "") -> str:
    return (
        f'<div class="a-panel"{attrs}><div class="a-panel__head">'
        f'<h3 class="a-panel__title">{_esc(title)}</h3></div>{body}</div>'
    )


def _table(
    ident: str,
    label: str,
    head: Iterable[tuple[str, bool]],
    rows: list[str],
    empty: str,
    sticky: bool = False,
) -> str:
    if not rows:
        return f'<p class="a-empty">{empty}</p>'
    cells = "".join(
        f'<th scope="col"{" data-numeric" if num else ""}>{_esc(name)}</th>' for name, num in head
    )
    sticky_attr = ' data-a-sticky-columns="1"' if sticky else ""
    return (
        f'<div class="a-table-scroll" tabindex="0" role="region" aria-label="{_esc(label)}">'
        f'<table class="a-table" id="{ident}"{sticky_attr}><caption class="a-visually-hidden">'
        f"{_esc(label)}</caption><thead><tr>{cells}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _filter(target: str, attr: str, label: str, options: Iterable[tuple[str, str]]) -> str:
    opts = "".join(f'<option value="{_esc(v)}">{_esc(t)}</option>' for v, t in options)
    ident = f"{target}-filter-{attr}"
    return (
        f'<div class="a-toolbar"><label class="a-label" for="{ident}">{_esc(label)}</label>'
        f'<select class="a-select" id="{ident}" data-a-filter="#{_esc(target)}" '
        f'data-a-filter-key="{_esc(attr)}"><option value="all">All</option>{opts}'
        f"</select></div>"
    )


def _chart(kind: str, label: str, unit: str, table: str, extra: str = "") -> str:
    return (
        f'<div role="figure" aria-label="{_esc(label)}" data-a-chart="{kind}" '
        f'data-a-chart-label="{_esc(label)}" data-a-chart-unit="{_esc(unit)}"'
        f' data-a-chart-empty="No measured values for this selection.">{extra}'
        f'<p class="a-label">{_esc(label)}</p>{table}</div>'
    )


def _meta(pairs: Iterable[tuple[str, str]]) -> str:
    items = "".join(
        f'<div><dt>{_esc(k)}</dt><dd style="overflow-wrap:anywhere">{v}</dd></div>'
        for k, v in pairs
    )
    return f'<dl class="a-meta-list">{items}</dl>'


def _ul(items: Iterable[str]) -> str:
    body = "".join(f"<li>{item}</li>" for item in items)
    return f"<ul>{body}</ul>" if body else ""


def _callout(title: str, body: str, risk: bool = False) -> str:
    kind = " a-callout--risk" if risk else ""
    role = ' role="note"'
    return (
        f'<div class="a-callout{kind}"{role}><p class="a-callout__title">{_esc(title)}</p>'
        f"{body}</div>"
    )


def _metric(label: str, value: str, detail: str, state: str | None = None) -> str:
    shown = _status(value, state) if state else _esc(value)
    status = f'<p class="a-metric__value">{shown}</p>'
    return (
        f'<div class="a-metric"><p class="a-metric__label">{_esc(label)}</p>{status}'
        f'<p class="a-metric__delta">{detail}</p></div>'
    )


def _missing_note(ev: Evidence, area: str, word: str = "UNTESTED") -> str:
    if ev.status == INVALID:
        reason = _Text()(ev.error, 300, "invalid")
        return _callout(
            f"{area}: {word} \u2014 {ev.filename} rejected",
            f"<p>{_esc(ev.filename)} could not be used: {reason}."
            " Nothing from this file is shown or counted.</p>",
            risk=True,
        )
    return _callout(
        f"{area}: {word}",
        f"<p>No {_esc(ev.filename)} was found in the results directory, so this area "
        f"is {word.lower()}. Absence of evidence is not a pass.</p>",
    )


# --------------------------------------------------------------------------- report


class _Report:
    def __init__(self, evidence: dict[str, Evidence]) -> None:
        self.ev = evidence
        self.t = _Text()

    def data(self, key: str) -> dict[str, Any] | None:
        item = self.ev.get(key)
        return item.data if item is not None and item.loaded else None

    def assets(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
        for key in ("inventory", "cbom"):
            data = self.data(key)
            if data is not None:
                return list(data["assets"]), list(data.get("errors", [])), EVIDENCE_FILES[key]
        return [], [], None

    # ----------------------------------------------------------------- summary
    def summary(self) -> str:
        t = self.t
        plan, pol, mx, bm = (
            self.data(k) for k in ("migration_plan", "policy", "matrix", "benchmark")
        )
        assets, errors, source = self.assets()
        metrics = []
        if plan is not None:
            metrics.append(
                _metric(
                    "Migration readiness",
                    plan["readiness"],
                    f"profile {t(plan['profile'])}, policy {t(plan['policy_id'])}",
                    READINESS_STATE[plan["readiness"]],
                )
            )
        else:
            metrics.append(
                _metric(
                    "Migration readiness", "UNKNOWN", "no usable migration-plan.json", "planned"
                )
            )
        if source is not None:
            metrics.append(
                _metric(
                    "Inventoried assets",
                    f"{len(assets):,}",
                    f"{len(errors):,} discovery error(s); from {_esc(source)}",
                )
            )
        else:
            metrics.append(
                _metric("Inventoried assets", "UNKNOWN", "no usable inventory", "planned")
            )
        if pol is not None:
            s = pol["summary"]
            bad = s["total_assets"] - s["compliant"]
            metrics.append(
                _metric(
                    "Policy non-compliant",
                    f"{bad:,} of {s['total_assets']:,}",
                    f"{s['quantum_vulnerable']:,} quantum-vulnerable; "
                    f"{s['evidence_incomplete']:,} with incomplete evidence",
                )
            )
        else:
            metrics.append(
                _metric("Policy evaluation", "UNKNOWN", "no usable policy.json", "planned")
            )
        if mx is not None:
            rows = mx["rows"]
            ok = sum(1 for r in rows if r["status"] == tls.SUCCESS)
            passing = sum(1 for r in rows if r.get("policy_pass") is True)
            metrics.append(
                _metric(
                    "TLS matrix handshakes",
                    f"{ok:,} of {len(rows):,} succeeded",
                    f"{passing:,} row(s) met the matrix TLS policy",
                )
            )
        else:
            metrics.append(_metric("TLS interop", "UNTESTED", "no usable matrix.json", "planned"))
        if bm is not None:
            counts = Counter(r["status"] for r in bm["results"])
            metrics.append(
                _metric(
                    "Benchmark entries",
                    f"{counts['SUCCESS']:,} of {len(bm['results']):,} measured",
                    f"n = {bm['methodology']['iterations']:,} samples per operation",
                )
            )
        else:
            metrics.append(_metric("Benchmarks", "UNTESTED", "no usable benchmark.json", "planned"))
        observations: list[str] = []
        if plan is not None:
            observations += [t(r, 400) for r in plan["reasons"][:8]]
        invalid = [e for e in self.ev.values() if e.status == INVALID]
        missing = [
            e for e in self.ev.values() if e.status == MISSING and e.key not in OPTIONAL_EVIDENCE
        ]
        if invalid:
            observations.append(
                f"{len(invalid)} evidence file(s) were rejected and are treated "
                "as unknown: " + ", ".join(_esc(e.filename) for e in invalid)
            )
        if missing:
            observations.append(
                f"{len(missing)} evidence file(s) are missing; those areas are "
                "untested: " + ", ".join(_esc(e.filename) for e in missing)
            )
        if mx is not None:
            ok_fail = sum(
                1
                for r in mx["rows"]
                if r["status"] == tls.SUCCESS and r.get("policy_pass") is False
            )
            if ok_fail:
                observations.append(
                    f"{ok_fail} matrix handshake(s) connected but did not meet "
                    "the TLS policy; connecting is not the same as compliant."
                )
        if bm is not None and bm["methodology"]["iterations"] < benchmark.P95_MIN_SAMPLES:
            observations.append(
                f"Benchmarks used {bm['methodology']['iterations']} samples per "
                f"operation; p95 is not reported below "
                f"{benchmark.P95_MIN_SAMPLES} samples."
            )
        obs = _panel("Key observations", _ul(observations)) if observations else ""
        return _section(
            "summary",
            "Executive summary",
            f'<div class="a-grid">{"".join(metrics)}</div>{obs}{self.provenance()}',
            "Each figure below is derived from the evidence files listed under "
            "Evidence provenance. Missing evidence is shown as UNTESTED or UNKNOWN "
            "and never as a pass.",
        )

    def provenance(self) -> str:
        rows = []
        for key, name in EVIDENCE_FILES.items():
            ev = self.ev[key]
            if ev.status == LOADED:
                chip = _status("Loaded", "active")
                note = "schema checked"
            elif ev.status == MISSING:
                chip = _status(
                    "Missing \u2014 optional"
                    if key in OPTIONAL_EVIDENCE
                    else "Missing \u2014 untested",
                    "planned",
                )
                note = "not present in results directory"
            else:
                chip = _status("Invalid \u2014 not used", "blocked")
                note = self.t(ev.error, 300, "invalid")
            size = f"{ev.size_bytes:,}" if ev.size_bytes is not None else "\u2014"
            digest = f"<code>{_esc(ev.sha256[:16])}\u2026</code>" if ev.sha256 else "\u2014"
            rows.append(
                f'<tr data-status="{_slug(ev.status)}"><td><code>{_esc(name)}</code>'
                f"</td><td>{chip}</td><td data-numeric>{size}</td><td>{digest}</td>"
                f"<td>{note}</td></tr>"
            )
        table = _table(
            "evidence-files",
            "Evidence files",
            [
                ("File", False),
                ("Status", False),
                ("Bytes", True),
                ("SHA-256 (prefix)", False),
                ("Notes", False),
            ],
            rows,
            "",
        )
        return _panel("Evidence provenance", table + self.consistency())

    def consistency(self) -> str:
        inv, pol, plan, cb, mx, bm, caps = (
            self.data(k)
            for k in (
                "inventory",
                "policy",
                "migration_plan",
                "cbom",
                "matrix",
                "benchmark",
                "capabilities",
            )
        )
        checks: list[tuple[str, bool | None, str]] = []

        def check(name: str, ok: bool | None, detail: str) -> None:
            checks.append((name, ok, detail))

        if inv is not None and pol is not None:
            ok = {a["asset_id"] for a in inv["assets"]} == {f["asset_id"] for f in pol["findings"]}
            check(
                "Inventory assets match policy findings",
                ok,
                f"{len(inv['assets'])} asset(s) vs {len(pol['findings'])} finding(s)",
            )
        else:
            check("Inventory assets match policy findings", None, "needs inventory and policy")
        if pol is not None and plan is not None:
            ok = pol["policy_digest"] == plan["policy_digest"] and {
                f["asset_id"] for f in pol["findings"]
            } == {i["asset_id"] for i in plan["items"]}
            check(
                "Policy and plan use the same policy and assets",
                ok,
                "policy digest and asset IDs compared",
            )
        else:
            check(
                "Policy and plan use the same policy and assets",
                None,
                "needs policy and migration plan",
            )
        if inv is not None and cb is not None:
            ok = {a["asset_id"] for a in inv["assets"]} == {a["asset_id"] for a in cb["assets"]}
            check("CBOM matches inventory", ok, "asset IDs compared")
        versions = []
        if caps is not None:
            versions.append(("capabilities", caps["openssl"].get("version")))
        if mx is not None:
            versions.append(("matrix", _obj_get(mx["environment"], "openssl", "version")))
        if bm is not None:
            versions.append(("benchmark", _obj_get(bm["environment"], "openssl", "version")))
        known = [(n, v) for n, v in versions if isinstance(v, str)]
        if len(known) >= 2:
            check(
                "Same OpenSSL build across evidence",
                len({v for _, v in known}) == 1,
                "; ".join(f"{n}: {self.t(v, 80)}" for n, v in known),
            )
        else:
            check(
                "Same OpenSSL build across evidence",
                None,
                "needs at least two of capabilities, matrix, benchmark",
            )
        rows = []
        for name, result, detail in checks:
            if result is None:
                chip = _status("Not checked", "planned")
            elif result:
                chip = _status("Consistent", "done")
            else:
                chip = _status("Mismatch", "blocked")
            rows.append(f"<tr><td>{_esc(name)}</td><td>{chip}</td><td>{detail}</td></tr>")
        return '<h4 class="a-label">Cross-file consistency</h4>' + _table(
            "consistency",
            "Cross-file consistency checks",
            [("Check", False), ("Result", False), ("Detail", False)],
            rows,
            "",
        )

    # ----------------------------------------------------------------- inventory
    def inventory(self) -> str:
        t = self.t
        assets, errors, source = self.assets()
        if source is None:
            return _section(
                "inventory",
                "Cryptographic inventory",
                _missing_note(self.ev["inventory"], "Inventory", "UNKNOWN"),
            )
        rows = []
        ordered = sorted(assets, key=lambda a: (a["asset_type"], a["source"], a["asset_id"]))
        for a in ordered:
            ev = a.get("evidence", {})
            params = [
                a.get("parameter_set"),
                f"{a['key_size']} bits" if a.get("key_size") is not None else None,
                a.get("signature_algorithm"),
                a.get("tls_version"),
                a.get("negotiated_group"),
                a.get("cipher_suite"),
            ]
            params_text = ", ".join(dict.fromkeys(t.raw(p, 80) for p in params if p)) or ""
            standard = " / ".join(
                x
                for x in (
                    t.raw(_scalar(ev.get("algorithm_standard")), 80),
                    t.raw(_scalar(ev.get("integration_status")), 80),
                )
                if x
            )
            validity = a.get("expiry") or _scalar(ev.get("validity"))
            if a.get("expiry") and _scalar(ev.get("validity")):
                validity = f"{ev['validity']} (expires {a['expiry']})"
            rows.append(
                f'<tr data-type="{_slug(a["asset_type"])}">'
                f"<td><code>{t(a['asset_id'], 64)}</code></td>"
                f"<td>{t(a['asset_type'])}</td><td>{t(a.get('algorithm'))}</td>"
                f"<td>{_esc(params_text) or '&#8212;'}</td>"
                f"<td>{t(_scalar(ev.get('crypto_class')), 60, 'unclassified')}</td>"
                f"<td>{_esc(standard) or '&#8212;'}</td><td>{t(a['source'], 120)}</td>"
                f"<td>{t(a.get('certificate_subject'), 120)}</td><td>{t(validity, 80)}</td></tr>"
            )
        types = sorted({(_slug(a["asset_type"]), t.raw(a["asset_type"], 60)) for a in assets})
        table = _table(
            "inventory-table",
            "Inventoried assets",
            [
                ("Asset ID", False),
                ("Type", False),
                ("Algorithm", False),
                ("Parameters", False),
                ("Class", False),
                ("Standard / integration", False),
                ("Source", False),
                ("Subject", False),
                ("Validity", False),
            ],
            rows,
            "The scan found no cryptographic assets.",
            sticky=True,
        )
        err_rows = [
            f"<tr><td>{t(e['source'], 120)}</td><td><code>{t(e['code'], 60)}</code></td>"
            f"<td>{t(e['message'], 300)}</td></tr>"
            for e in sorted(errors, key=lambda e: (e["source"], e["code"]))
        ]
        err_table = _table(
            "discovery-errors",
            "Discovery errors",
            [("Source", False), ("Code", False), ("Message", False)],
            err_rows,
            "No discovery errors were recorded.",
        )
        lead = (
            f"{len(assets):,} asset(s) from <code>{_esc(source)}</code>. Private key "
            "material is never reproduced; keys are identified by a hash of the derived "
            "public key."
        )
        if source != EVIDENCE_FILES["inventory"]:
            lead += " inventory.json was not usable, so the CBOM asset list is shown instead."
        return _section(
            "inventory",
            "Cryptographic inventory",
            _panel("Assets", _filter("inventory-table", "type", "Asset type", types) + table)
            + _panel("Discovery errors", err_table),
            lead,
        )

    # ----------------------------------------------------------------- classification
    def classification(self) -> str:
        t = self.t
        parts = []
        assets, _, source = self.assets()
        if source is not None:
            counts = Counter(
                t.raw(_scalar(a.get("evidence", {}).get("crypto_class")), 60) or "unclassified"
                for a in assets
            )
            rows = [
                f"<tr><td>{_esc(name)}</td><td data-numeric>{n}</td></tr>"
                for name, n in sorted(counts.items())
            ]
            parts.append(
                _panel(
                    "Assets by cryptographic class",
                    _chart(
                        "bar",
                        "Assets by cryptographic class",
                        "assets",
                        _table(
                            "class-chart",
                            "Assets by cryptographic class",
                            [("Class", False), ("Assets", True)],
                            rows,
                            "No assets.",
                        ),
                    ),
                )
            )
        else:
            parts.append(_missing_note(self.ev["inventory"], "Asset classification", "UNKNOWN"))
        caps = self.data("capabilities")
        if caps is None:
            parts.append(
                _missing_note(self.ev["capabilities"], "Local algorithm support", "UNKNOWN")
            )
            return _section("classification", "Algorithm classification", "".join(parts))
        std, groups = caps["standardized"], caps["tls_group_classes"]
        x509 = sorted(name for name, v in caps["x509"].items() if v.get("supported") is True)
        lines = [
            ("ML-KEM", "NIST FIPS 203", "Standardized algorithm", std["ml_kem"]),
            ("ML-DSA", "NIST FIPS 204", "Standardized algorithm", std["ml_dsa"]),
            ("SLH-DSA", "NIST FIPS 205", "Standardized algorithm", std["slh_dsa"]),
            (
                "Hybrid TLS 1.3 groups",
                "IETF drafts / code points",
                "Lab experiment (TLS integration)",
                groups["hybrid"],
            ),
            (
                "Pure PQC TLS 1.3 groups",
                "IETF drafts / code points",
                "Lab experiment (TLS integration)",
                groups["pqc"],
            ),
            (
                "Classical TLS 1.3 groups",
                "RFC 8446 and related",
                "Classical; quantum-vulnerable key establishment",
                groups["classical"],
            ),
            (
                "X.509 certificate keys exercised",
                "PQ X.509 profiles still maturing",
                "Lab experiment for PQ keys",
                x509,
            ),
        ]
        rows = []
        for name, ref, status, values in lines:
            listed = ", ".join(t.raw(v, 60) for v in values[:40])
            avail = (
                _status(f"{len(values)} available locally", "active")
                if values
                else _status("Not available locally", "planned")
            )
            rows.append(
                f"<tr><td>{_esc(name)}</td><td>{_esc(ref)}</td><td>{_esc(status)}</td>"
                f"<td>{avail}</td><td>{_esc(listed) or '&#8212;'}</td></tr>"
            )
        support = _table(
            "support-table",
            "Local OpenSSL algorithm support",
            [
                ("Family", False),
                ("Reference", False),
                ("Standing", False),
                ("Local support", False),
                ("Names", False),
            ],
            rows,
            "",
        )
        prof_rows = []
        for name, p in sorted(caps["profiles"].items()):
            chip = (
                _status("Available locally", "active")
                if p["supported"]
                else _status("UNSUPPORTED locally", "planned")
            )
            missing = ", ".join(t.raw(m, 80) for m in p.get("missing", []))
            prof_rows.append(
                f"<tr><td>{t(name, 40)}</td><td>{t(p.get('group'))}</td>"
                f"<td>{t(p.get('group_kind'))}</td>"
                f"<td>{t(p.get('certificate_key'))}</td><td>{chip}</td>"
                f"<td>{_esc(missing) or '&#8212;'}</td></tr>"
            )
        profiles = _table(
            "profile-table",
            "Lab TLS profiles",
            [
                ("Profile", False),
                ("Group", False),
                ("Group kind", False),
                ("Certificate key", False),
                ("Support", False),
                ("Missing", False),
            ],
            prof_rows,
            "No profiles were recorded.",
        )
        providers = ", ".join(t.raw(p.get("name") or p.get("id"), 60) for p in caps["providers"])
        meta = _meta(
            [
                ("OpenSSL", t(caps["openssl"]["version"])),
                ("Providers", _esc(providers) or "&#8212;"),
                (
                    "oqs-provider",
                    "loaded"
                    if caps["oqs_provider_loaded"]
                    else "not loaded (not required for native OpenSSL 3.5 PQC)",
                ),
            ]
        )
        parts.append(_panel("Local OpenSSL support", meta + support))
        parts.append(_panel("Strict lab TLS profiles", profiles))
        return _section(
            "classification",
            "Algorithm classification",
            "".join(parts),
            "Standardized algorithms are distinguished from experimental TLS and "
            "X.509 integrations. Local support means the OpenSSL build used here "
            "exposes the name; it is not an interoperability claim.",
        )

    # ----------------------------------------------------------------- findings
    def findings(self) -> str:
        t = self.t
        parts = []
        plan = self.data("migration_plan")
        if plan is not None:
            reasons = _ul(t(r, 400) for r in plan["reasons"]) or "<p>No reasons recorded.</p>"
            parts.append(
                _callout(
                    f"Readiness: {plan['readiness']}", reasons, risk=plan["readiness"] != "READY"
                )
            )
            by_priority = plan["summary"]["by_priority"]
            prow = [
                f"<tr><td>{p}</td><td data-numeric>{by_priority.get(p, 0)}</td></tr>"
                for p in policy.PRIORITIES
            ]
            parts.append(
                _panel(
                    "Assets by migration priority",
                    _chart(
                        "bar",
                        "Assets by migration priority",
                        "assets",
                        _table(
                            "priority-chart",
                            "Assets by migration priority",
                            [("Priority", False), ("Assets", True)],
                            prow,
                            "",
                        ),
                    ),
                )
            )
            order = {p: i for i, p in enumerate(policy.PRIORITIES)}
            rows = []
            for item in sorted(plan["items"], key=lambda i: (order[i["priority"]], i["asset_id"])):
                blocker = (
                    f"{_status(item['blocker_kind'], 'blocked')} {t(item['blocker'], 400)}"
                    if item["blocker"]
                    else "&#8212;"
                )
                rows.append(
                    f'<tr data-priority="{_slug(item["priority"])}">'
                    f"<td><code>{t(item['asset_id'], 64)}</code></td>"
                    f"<td>{_status(item['priority'], PRIORITY_STATE[item['priority']])}</td>"
                    f"<td>{t(item['current_algorithm'])}</td>"
                    f"<td>{_status(item['outcome'], OUTCOME_STATE[item['outcome']])}</td>"
                    f"<td>{'yes' if item['ready'] else 'no'}</td><td>{blocker}</td>"
                    f"<td>{t(item['dependency'], 400)}</td>"
                    f"<td>{t(item['recommended_test'], 300)}</td>"
                    f"<td>{t(item['next_action'], 300)}</td></tr>"
                )
            options = [(_slug(p), p) for p in policy.PRIORITIES]
            parts.append(
                _panel(
                    "Migration plan items",
                    _filter("plan-table", "priority", "Priority", options)
                    + _table(
                        "plan-table",
                        "Migration plan items",
                        [
                            ("Asset", False),
                            ("Priority", False),
                            ("Current algorithm", False),
                            ("Outcome", False),
                            ("Ready", False),
                            ("Blocker", False),
                            ("Dependency", False),
                            ("Recommended test", False),
                            ("Next action", False),
                        ],
                        rows,
                        "The plan lists no assets.",
                        sticky=True,
                    ),
                )
            )
            parts.append(self.blockers(plan))
        else:
            parts.append(_missing_note(self.ev["migration_plan"], "Migration readiness", "UNKNOWN"))
        pol = self.data("policy")
        if pol is not None:
            rows = []
            for f in sorted(pol["findings"], key=lambda f: (f["outcome"], f["asset_id"])):
                qv = f.get("quantum_vulnerable")
                qv_text = "unknown" if qv is None else ("yes" if qv else "no")
                opts = f["migration_options"]
                options_html = (
                    f'<details class="a-disclosure"><summary>{len(opts)} option(s)'
                    f"</summary>{_ul(t(o, 300) for o in opts[:12])}</details>"
                    if opts
                    else "&#8212;"
                )
                rows.append(
                    f'<tr data-outcome="{_slug(f["outcome"])}">'
                    f"<td><code>{t(f['asset_id'], 64)}</code></td>"
                    f"<td>{t(f['asset_type'])}</td><td>{t(f['current_algorithm'])}</td>"
                    f"<td>{_status(f['outcome'], OUTCOME_STATE[f['outcome']])}</td>"
                    f"<td>{t(f['evidence_status'])}</td><td>{qv_text}</td>"
                    f"<td>{_ul(t(r, 400) for r in f['reasons'][:8])}</td>"
                    f"<td>{options_html}</td></tr>"
                )
            options = [(_slug(o), o) for o in policy.OUTCOMES]
            meta = _meta(
                [
                    ("Policy", t(pol["policy_id"])),
                    ("Policy digest", f"<code>{t(pol['policy_digest'], 80)}</code>"),
                    ("Evaluated at", t(pol["evaluated_at"])),
                ]
            )
            parts.append(
                _panel(
                    "Policy findings",
                    meta
                    + _filter("findings-table", "outcome", "Outcome", options)
                    + _table(
                        "findings-table",
                        "Policy findings",
                        [
                            ("Asset", False),
                            ("Type", False),
                            ("Algorithm", False),
                            ("Outcome", False),
                            ("Evidence", False),
                            ("Quantum-vulnerable", False),
                            ("Why", False),
                            ("Migration options", False),
                        ],
                        rows,
                        "The policy evaluation lists no findings.",
                        sticky=True,
                    ),
                )
            )
        else:
            parts.append(_missing_note(self.ev["policy"], "Policy findings", "UNKNOWN"))
        return _section(
            "findings",
            "Findings, priorities and blockers",
            "".join(parts),
            "Every outcome carries the policy rule and evidence that produced it. "
            "Assets with missing or unrecognised evidence stay UNKNOWN.",
        )

    def blockers(self, plan: dict[str, Any]) -> str:
        groups: dict[str, list[str]] = {}
        for item in sorted(plan["items"], key=lambda i: i["asset_id"]):
            if item["blocker"]:
                groups.setdefault(item["blocker_kind"], []).append(
                    f"<code>{self.t(item['asset_id'], 64)}</code>: {self.t(item['blocker'], 400)}"
                )
        if not groups:
            return _panel("Blockers", '<p class="a-empty">The plan records no blockers.</p>')
        body = "".join(
            f'<h4 class="a-label">{_esc(kind)} ({len(groups[kind])})</h4>{_ul(groups[kind])}'
            for kind in migration.BLOCKER_KINDS
            if kind in groups
        )
        return _panel("Blockers", body)

    # ----------------------------------------------------------------- interop
    def interop(self) -> str:
        mx = self.data("matrix")
        if mx is None:
            return _section(
                "interop",
                "TLS interoperability matrix",
                _missing_note(self.ev["matrix"], "TLS interoperability"),
            )
        t = self.t
        rows = mx["rows"]
        clients = list(dict.fromkeys(r["client"] for r in rows))
        servers = list(dict.fromkeys(r["server"] for r in rows))
        cells: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for r in rows:
            cells.setdefault((r["client"], r["server"]), []).append(r)
        head = [("Client \\ server", False)] + [(t.raw(s, 40), False) for s in servers]
        pivot_rows = []
        for c in clients:
            tds = []
            for s in servers:
                found = cells.get((c, s), [])
                tds.append(
                    "<td>"
                    + (
                        " ".join(
                            _status(r["status"], MATRIX_STATE[r["status"]])
                            + (
                                f" <small>{t(r.get('negotiated_group'), 40)}</small>"
                                if r.get("negotiated_group")
                                else ""
                            )
                            for r in found
                        )
                        or '<span class="a-label">not run</span>'
                    )
                    + "</td>"
                )
            pivot_rows.append(f'<tr><th scope="row">{t(c, 40)}</th>{"".join(tds)}</tr>')
        pivot = _table(
            "interop-pivot", "Client by server outcome", head, pivot_rows, "", sticky=True
        )
        detail = []
        for index, r in enumerate(rows):
            pp = r.get("policy_pass")
            pchip = (
                _status("not evaluated", "planned")
                if pp is None
                else _status("pass", "done")
                if pp
                else _status("fail", "blocked")
            )
            experiment = (
                "negative control (failure expected)"
                if r.get("experiment") == "negative"
                else t(r.get("experiment"))
            )
            reason = r.get("error_reason") or "; ".join(r.get("policy_reasons", []))
            group = r.get("negotiated_group")
            kind = r.get("negotiated_group_kind")
            hb_r, hb_w = r.get("handshake_bytes_read"), r.get("handshake_bytes_written")
            hb = (
                f"{hb_r:,} / {hb_w:,}"
                if isinstance(hb_r, int) and isinstance(hb_w, int)
                else ("&#8212;")
            )
            detail.append(
                f'<tr data-status="{_slug(r["status"])}"><td>{index}</td>'
                f"<td>{t(r['client'], 40)}</td><td>{t(r['server'], 40)}</td>"
                f"<td>{experiment}</td><td>{_status(r['status'], MATRIX_STATE[r['status']])}</td>"
                f"<td>{t(group)}{f' ({t(kind)})' if kind else ''}</td>"
                f"<td>{t(r.get('tls_version'))}</td>"
                f"<td>{t(r.get('certificate_type'))}</td>"
                f"<td>{t(r.get('peer_signature_type'))}</td><td>{pchip}</td>"
                f"<td data-numeric>{hb}</td><td data-numeric>{_ms(r.get('client_process_ms'))}"
                f"</td><td>{t(reason, 300)}</td></tr>"
            )
        statuses = [(_slug(s), s) for s in tls.STATUSES]
        table = _filter("interop-table", "status", "Status", statuses) + _table(
            "interop-table",
            "TLS matrix rows",
            [
                ("Row", True),
                ("Client", False),
                ("Server", False),
                ("Experiment", False),
                ("Status", False),
                ("Negotiated group", False),
                ("TLS", False),
                ("Certificate", False),
                ("Peer signature", False),
                ("Matrix policy", False),
                ("Handshake bytes read / written", True),
                ("Client process ms", True),
                ("Reason", False),
            ],
            detail,
            "The matrix contains no rows.",
            sticky=True,
        )
        env = mx["environment"]
        pol = mx.get("policy", {})
        kinds = pol.get("allowed_group_kinds")
        kinds_text = ", ".join(t.raw(k, 30) for k in kinds) if isinstance(kinds, list) else ""
        meta = _meta(
            [
                ("Generated", t(env.get("generated_at"))),
                ("OpenSSL", t(_obj_get(env, "openssl", "version"))),
                ("Legacy client", t(env.get("legacy_client"), 160, "not available (UNTESTED)")),
                (
                    "Matrix policy",
                    f"{t(_scalar(pol.get('name')))}; allowed group kinds: "
                    f"{_esc(kinds_text) or '&#8212;'}",
                ),
                ("Latency semantics", t(env.get("latency_semantics"), 400)),
                ("Standardization", t(env.get("standardization"), 400)),
            ]
        )
        return _section(
            "interop",
            "TLS interoperability matrix",
            _panel("Outcome by client and server", pivot)
            + _panel("Matrix rows", table)
            + _panel("Matrix environment", meta),
            "Status records whether the handshake completed; the matrix policy "
            "column separately records whether the negotiated parameters met the "
            "policy. Negative controls are expected to fail.",
        )

    # ----------------------------------------------------------------- performance
    def performance(self) -> str:
        bm = self.data("benchmark")
        if bm is None:
            return _section(
                "performance",
                "Latency and sizes",
                _missing_note(self.ev["benchmark"], "Benchmarks"),
            )
        t = self.t
        method = bm["methodology"]
        n = method["iterations"]
        results = bm["results"]
        baseline = next(
            (r for r in results if r["kind"] == "baseline" and r["status"] == "SUCCESS"), None
        )
        base_ms = _stat(baseline, "process", "median_ms") if baseline else None
        caveat_items = [
            f"n = {n} measured samples per operation after {method['warmups']} discarded warmups."
        ]
        if n < benchmark.P95_MIN_SAMPLES:
            caveat_items.append(
                f"p95 is not reported: fewer than {benchmark.P95_MIN_SAMPLES} "
                "samples. Medians from small samples are indicative only."
            )
        caveat_items.append(
            "Each sample is a whole OpenSSL CLI process (fork/exec, provider "
            "load, key parsing, I/O, then the operation), not an in-library "
            "primitive latency. Compare against the baseline entry."
        )
        if base_ms is not None:
            caveat_items.append(
                f"Baseline (openssl version, no cryptography) median: {_ms(base_ms)} ms."
            )
        else:
            caveat_items.append("No successful baseline entry; process overhead is UNKNOWN.")
        parts = [
            _callout("Read these numbers with care", _ul(_esc(c) for c in caveat_items), risk=True)
        ]
        tabs = []
        for kind, title, ops in (
            ("signature", "Signatures", ("keygen", "sign", "verify")),
            ("kem", "KEMs", ("keygen", "encapsulate", "decapsulate")),
            ("tls_handshake", "TLS handshakes", ("handshake",)),
        ):
            entries = [r for r in results if r["kind"] == kind and r["status"] == "SUCCESS"]
            rows = []
            for r in entries:
                medians = [_stat(r, op, "median_ms") for op in ops]
                tds = "".join(
                    f'<td data-numeric data-value="{_esc(_val(m))}">{_ms(m)}</td>' for m in medians
                )
                rows.append(f"<tr><td>{t(_label(r), 60)}</td>{tds}</tr>")
            ident = f"latency-{_slug(kind)}"
            table = _table(
                ident,
                f"{title} median latency (ms)",
                [("Entry", False)] + [(f"{op} median", True) for op in ops],
                rows,
                f"No successful {_esc(title.lower())} measurements (UNTESTED).",
            )
            tabs.append(
                (
                    ident,
                    title,
                    _chart("bar", f"{title}: median ms per operation", "ms", table)
                    if rows
                    else table,
                )
            )
        parts.append(_panel("Median latency by operation", _tabs("latency", tabs)))
        parts.append(_panel("All measured statistics", self.stats_table(results, base_ms, n)))
        parts.append(_panel("Sizes", self.sizes(results)))
        failed = [r for r in results if r["status"] != "SUCCESS"]
        if failed:
            rows = [
                f"<tr><td>{t(r['id'], 80)}</td>"
                f"<td>{_status(r['status'], BENCH_STATE[r['status']])}</td>"
                f"<td>{t(r.get('reason'), 300, 'no reason recorded')}</td></tr>"
                for r in failed
            ]
            parts.append(
                _panel(
                    "Not measured",
                    _table(
                        "bench-failed",
                        "Benchmark entries without measurements",
                        [("Entry", False), ("Status", False), ("Reason", False)],
                        rows,
                        "",
                    ),
                )
            )
        return _section(
            "performance",
            "Latency and sizes",
            "".join(parts),
            "Charts are drawn from the tables under each chart; the tables hold the exact values.",
        )

    def stats_table(self, results: list[dict[str, Any]], base_ms: float | None, n: int) -> str:
        t = self.t
        rows = []
        for r in results:
            if r["status"] != "SUCCESS":
                continue
            ops = r.get("operations", {})
            for op in sorted(ops, key=lambda o: (OP_ORDER.index(o) if o in OP_ORDER else 99, o)):
                s = ops[op].get("statistics", {})
                p95 = s.get("p95_ms")
                p95_text = (
                    _ms(p95)
                    if p95 is not None
                    else (f"not reported (n = {s.get('count')} &lt; {benchmark.P95_MIN_SAMPLES})")
                )
                ratio = (
                    f"{s['median_ms'] / base_ms:,.2f}\u00d7"
                    if base_ms
                    and r["kind"] != "baseline"
                    and isinstance(s.get("median_ms"), int | float)
                    else "&#8212;"
                )
                rows.append(
                    f'<tr data-kind="{_slug(r["kind"])}"><td>'
                    f"{t(_label(r), 60)}</td><td>{t(op, 30)}</td>"
                    f"<td data-numeric>{t(s.get('count'))}</td>"
                    f"<td data-numeric>{_ms(s.get('median_ms'))}</td>"
                    f"<td data-numeric>{p95_text}</td>"
                    f"<td data-numeric>{_ms(s.get('min_ms'))}</td>"
                    f"<td data-numeric>{_ms(s.get('max_ms'))}</td>"
                    f"<td data-numeric>{ratio}</td></tr>"
                )
        kinds = sorted({(_slug(r["kind"]), t.raw(r["kind"], 30)) for r in results})
        return _filter("stats-table", "kind", "Kind", kinds) + _table(
            "stats-table",
            "Benchmark statistics",
            [
                ("Entry", False),
                ("Operation", False),
                ("n", True),
                ("Median ms", True),
                ("p95 ms", True),
                ("Min ms", True),
                ("Max ms", True),
                ("Median vs baseline", True),
            ],
            rows,
            "No successful measurements.",
            sticky=True,
        )

    def sizes(self, results: list[dict[str, Any]]) -> str:
        t = self.t
        tabs = []
        for kind, title, cols in (
            (
                "signature",
                "Signatures",
                (("public_key_der_bytes", "Public key DER"), ("signature_bytes", "Signature")),
            ),
            (
                "kem",
                "KEMs",
                (("public_key_der_bytes", "Public key DER"), ("ciphertext_bytes", "Ciphertext")),
            ),
            (
                "tls_handshake",
                "TLS handshakes",
                (
                    ("leaf_certificate_der_bytes", "Leaf certificate DER"),
                    ("served_chain_der_bytes", "Served chain DER"),
                    ("handshake_bytes_total", "Handshake bytes (client counters)"),
                ),
            ),
        ):
            rows = []
            for r in results:
                if r["kind"] != kind or r["status"] != "SUCCESS":
                    continue
                sizes = r.get("sizes", {})
                tds = ""
                for key, _ in cols:
                    text, value = _bytes(sizes.get(key))
                    tds += f'<td data-numeric data-value="{_esc(value)}">{text}</td>'
                rows.append(f"<tr><td>{t(_label(r), 60)}</td>{tds}</tr>")
            ident = f"sizes-{_slug(kind)}"
            table = _table(
                ident,
                f"{title} sizes (bytes)",
                [("Entry", False)] + [(f"{label} bytes", True) for _, label in cols],
                rows,
                f"No successful {_esc(title.lower())} size measurements.",
            )
            tabs.append(
                (
                    ident,
                    title,
                    _chart("bar", f"{title}: sizes in bytes", "B", table) if rows else table,
                )
            )
        return _tabs("sizes", tabs)

    # ----------------------------------------------------------------- footprint
    def footprint(self) -> str:
        t = self.t
        parts = []
        plan = self.data("migration_plan")
        if plan is not None:
            fp = plan["footprint"]
            measured = fp["status"] == "measured"
            chip = (
                _status("Measured", "active")
                if measured
                else _status("UNKNOWN \u2014 not measured", "planned")
            )
            label = t(fp.get("label"), 200) if fp.get("label") else _esc(migration.ESTIMATE_LABEL)
            budget = fp.get("declared_budget_bytes")
            within = fp.get("within_declared_budget")
            meta = [("Status", chip), ("Statement", t(fp["statement"], 600))]
            if measured:
                meta.append(("Label", label))
            meta.append(
                ("Declared budget", f"{budget:,} bytes" if budget is not None else "none declared")
            )
            meta.append(
                ("Within budget", "unknown" if within is None else ("yes" if within else "no"))
            )
            rows = [
                f"<tr><td>{t(m['group_rule_id'], 60)}</td><td data-numeric>{m['samples']}"
                f"</td><td data-numeric>{_num(m['median_handshake_bytes'])}</td>"
                f"<td data-numeric>{_num(m['min'])}</td><td data-numeric>{_num(m['max'])}"
                "</td></tr>"
                for m in fp["handshake_measurements"]
            ]
            table = _table(
                "footprint-table",
                "Measured handshake footprint",
                [
                    ("Group rule", False),
                    ("Samples", True),
                    ("Median bytes", True),
                    ("Min", True),
                    ("Max", True),
                ],
                rows,
                "No handshake byte measurements fed the plan; footprint is UNKNOWN.",
            )
            parts.append(_panel("Migration plan footprint", _meta(meta) + table))
        else:
            parts.append(_missing_note(self.ev["migration_plan"], "Footprint", "UNKNOWN"))
        mx = self.data("matrix")
        if mx is not None:
            by_kind: dict[str, list[int]] = {}
            for r in mx["rows"]:
                hr, hw = r.get("handshake_bytes_read"), r.get("handshake_bytes_written")
                if r["status"] == tls.SUCCESS and isinstance(hr, int) and isinstance(hw, int):
                    by_kind.setdefault(
                        t.raw(r.get("negotiated_group_kind"), 30) or "unknown", []
                    ).append(hr + hw)
            rows = [
                f"<tr><td>{_esc(k)}</td><td data-numeric>{len(v)}</td>"
                f"<td data-numeric>{min(v):,}</td><td data-numeric>{max(v):,}</td></tr>"
                for k, v in sorted(by_kind.items())
            ]
            parts.append(
                _panel(
                    "Observed handshake bytes in the matrix (read + written)",
                    _table(
                        "matrix-bytes",
                        "Matrix handshake bytes by group kind",
                        [
                            ("Negotiated group kind", False),
                            ("Rows", True),
                            ("Min bytes", True),
                            ("Max bytes", True),
                        ],
                        rows,
                        "No successful matrix rows reported byte counts.",
                    ),
                )
            )
        caveats = [
            "Byte counts are client-side OpenSSL TLS record counters for one loopback "
            "handshake; they exclude TCP/IP/Ethernet framing and are not packet captures.",
            "Session tickets are disabled and certificate chains are synthetic lab chains; "
            "real chains, intermediates, OCSP stapling and extensions change the footprint.",
            "No bandwidth, MTU, fragmentation or constrained-device estimate is made unless "
            "the plan explicitly reports measured values; anything else is UNKNOWN.",
        ]
        parts.append(_callout("Footprint caveats", _ul(_esc(c) for c in caveats), risk=True))
        return _section("footprint", "Footprint caveats", "".join(parts))

    # ----------------------------------------------------------------- methodology
    def methodology(self) -> str:
        t = self.t
        parts = []
        bm = self.data("benchmark")
        if bm is not None:
            env, m = bm["environment"], bm["methodology"]
            host, osinfo, py, ctr = env["host"], env["os"], env["python"], env["container"]
            ossl = env.get("openssl", {})
            parts.append(
                _panel(
                    "Benchmark environment",
                    _meta(
                        [
                            ("Timestamp (UTC)", t(env.get("timestamp_utc"))),
                            ("OpenSSL", t(ossl.get("version"))),
                            ("OpenSSL source", t(ossl.get("source"))),
                            ("OpenSSL config", t(ossl.get("config"))),
                            (
                                "CPU",
                                f"{t(host.get('cpu_model'))} ({t(host.get('architecture'))}, "
                                f"{t(host.get('logical_cpus'))} logical)",
                            ),
                            ("OS", f"{t(osinfo.get('distribution'))}; {t(osinfo.get('platform'))}"),
                            ("Python", f"{t(py.get('implementation'))} {t(py.get('version'))}"),
                            (
                                "Container / virtualization",
                                f"{t(ctr.get('runtime'), missing='none detected')} / "
                                f"{t(ctr.get('virtualization'), missing='unknown')}",
                            ),
                        ]
                    ),
                )
            )
            parts.append(
                _panel(
                    "Benchmark method",
                    _meta(
                        [
                            ("Clock", t(m.get("timing_clock"))),
                            ("Iterations", t(m["iterations"])),
                            ("Warmups", t(m["warmups"])),
                            ("Execution", t(m.get("execution"), 300)),
                            ("p95", t(m.get("p95_method"), 300)),
                            ("Operation scope", t(m.get("operation_scope"), 600)),
                            ("TLS timing scope", t(m.get("tls_timing_scope"), 600)),
                        ]
                    )
                    + _ul(t(c, 600) for c in m.get("caveats", [])),
                )
            )
        else:
            parts.append(_missing_note(self.ev["benchmark"], "Benchmark method"))
        pairs = []
        pol, plan = self.data("policy"), self.data("migration_plan")
        if pol is not None:
            pairs.append(
                ("Policy evaluation", f"{t(pol['policy_id'])} at {t(pol['evaluated_at'])}")
            )
        if plan is not None:
            pairs.append(
                ("Migration plan", f"profile {t(plan['profile'])} at {t(plan['generated_at'])}")
            )
        pairs.append(
            (
                "Report generation",
                "Offline. Evidence files are size-bounded strict "
                "JSON, schema-checked and escaped; secret-like strings are redacted; the "
                "page loads no remote assets and sends no telemetry.",
            )
        )
        parts.append(_panel("How this report was produced", _meta(pairs)))
        return _section("methodology", "Methodology", "".join(parts))

    # ----------------------------------------------------------------- limitations
    def limitations(self) -> str:
        items = [_esc(text) for text in LIMITATIONS]
        for ev in self.ev.values():
            if ev.status == MISSING and ev.key not in OPTIONAL_EVIDENCE:
                items.append(f"{_esc(ev.filename)} is missing; its area is UNTESTED/UNKNOWN.")
            elif ev.status == INVALID:
                items.append(
                    f"{_esc(ev.filename)} was rejected "
                    f"({self.t(ev.error, 300, 'invalid')}); its area is UNKNOWN."
                )
        bm = self.data("benchmark")
        if bm is not None and bm["methodology"]["iterations"] < benchmark.P95_MIN_SAMPLES:
            items.append(
                f"Benchmarks used only {bm['methodology']['iterations']} samples per "
                "operation; treat medians as indicative and p95 as unavailable."
            )
        mx = self.data("matrix")
        if mx is not None and not mx["environment"].get("legacy_client"):
            items.append(
                "No legacy (system OpenSSL) client was available; legacy "
                "interoperability is UNTESTED."
            )
        return _section("limitations", "Known limitations", _ul(items))

    def body(self) -> str:
        sections = [
            self.summary(),
            self.inventory(),
            self.classification(),
            self.findings(),
            self.interop(),
            self.performance(),
            self.footprint(),
            self.methodology(),
        ]
        limitations = self.limitations()
        if self.t.redactions:
            sections.append(
                _section(
                    "redactions",
                    "Redactions",
                    _callout(
                        "Secret-like content withheld",
                        f"<p>{self.t.redactions} value(s) looked like key material or TLS "
                        "secrets and were replaced with a redaction marker.</p>",
                        risk=True,
                    ),
                )
            )
        sections.append(limitations)
        nav = "".join(
            f'<a class="a-btn" href="#{i}">{_esc(n)}</a>'
            for i, n in (
                ("summary", "Summary"),
                ("inventory", "Inventory"),
                ("classification", "Classification"),
                ("findings", "Findings"),
                ("interop", "Interop"),
                ("performance", "Latency and sizes"),
                ("footprint", "Footprint"),
                ("methodology", "Methodology"),
                ("limitations", "Limitations"),
            )
        )
        return (
            f'<nav class="a-section a-toolbar" aria-label="Report sections">{nav}</nav>'
            + "".join(sections)
        )


def _obj_get(data: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _stat(entry: dict[str, Any] | None, op: str, name: str) -> Any:
    value = _obj_get(entry, "operations", op, "statistics", name)
    return value if isinstance(value, int | float) and not isinstance(value, bool) else None


def _val(value: Any) -> str:
    return "" if value is None else repr(float(value))


def _num(value: Any) -> str:
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.1f}"
    return "&#8212;"


def _label(entry: dict[str, Any]) -> str:
    if entry["kind"] == "tls_handshake" and entry.get("negotiated_group"):
        return f"{entry['id']} ({entry['negotiated_group']})"
    return str(entry["id"])


def _tabs(name: str, tabs: list[tuple[str, str, str]]) -> str:
    buttons = "".join(
        f'<button class="a-btn" type="button" role="tab" id="{name}-tab-{i}" '
        f'aria-controls="{name}-panel-{i}" aria-selected="{"true" if i == 0 else "false"}">'
        f"{_esc(title)}</button>"
        for i, (_, title, _) in enumerate(tabs)
    )
    panels = "".join(
        f'<div class="a-print-reveal" role="tabpanel" id="{name}-panel-{i}" tabindex="0" '
        f'aria-labelledby="{name}-tab-{i}"'
        f"{'' if i == 0 else ' hidden'}>{content}</div>"
        for i, (_, _, content) in enumerate(tabs)
    )
    return (
        f'<div class="a-toolbar" data-a-tabs role="tablist" aria-label="{_esc(name)} view">'
        f'<div class="a-tabs">{buttons}</div></div>{panels}'
    )


# --------------------------------------------------------------------------- shell and output


def load_shell() -> str:
    shell = (
        resources.files("cryptoagility.reporting")
        .joinpath(SHELL_RESOURCE)
        .read_text(encoding="utf-8")
    )
    if shell.count(BODY_MARKER) != 1:
        raise ReportError("packaged report shell is missing its body marker")
    scripts = re.findall(r"<script>(.*?)</script>", shell, re.S)
    pinned = re.search(r"script-src 'sha256-([A-Za-z0-9+/=]+)'", shell)
    if len(scripts) != 1 or pinned is None:
        raise ReportError("packaged report shell must have one CSP-pinned script")
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode()
    if digest != pinned.group(1):
        raise ReportError("packaged report shell script does not match its CSP hash")
    if re.search(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", shell, re.I):
        raise ReportError("packaged report shell references a remote asset")
    return shell


def render_html(evidence: dict[str, Evidence]) -> str:
    """Render the full report page from already-loaded evidence."""
    expected = set(EVIDENCE_FILES)
    if set(evidence) != expected:
        raise ReportError("evidence must contain exactly the known evidence keys")
    body = _Report(evidence).body()
    if "<script" in body.lower() or BODY_MARKER in body:
        raise ReportError("refusing to inject an unsafe report body")
    return load_shell().replace(BODY_MARKER, body, 1)


def _check_output(output: Path) -> Path:
    if output.suffix.lower() not in (".html", ".htm"):
        raise ReportError("output must be an .html file")
    parent = output.parent if str(output.parent) else Path(".")
    try:
        parent_info = os.stat(parent)
    except OSError:
        raise ReportError("output directory does not exist") from None
    if not stat.S_ISDIR(parent_info.st_mode):
        raise ReportError("output directory is not a directory")
    try:
        info = os.lstat(output)
    except FileNotFoundError:
        return parent
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReportError("output exists and is not a regular file (symlinks are refused)")
    return parent


def render_report(results_dir: Path | str, output: Path | str) -> Path:
    """Write a self-contained HTML report for the evidence in results_dir; return its path."""
    output = Path(output)
    parent = _check_output(output)
    try:
        evidence = load_evidence(Path(results_dir))
    except EvidenceError as exc:
        raise ReportError(str(exc)) from None
    page = render_html(evidence).encode("utf-8")
    if len(page) > MAX_REPORT_BYTES:
        raise ReportError("rendered report exceeds the size limit")
    handle = tempfile.NamedTemporaryFile(dir=parent, prefix=".report-", suffix=".tmp", delete=False)
    try:
        with handle:
            handle.write(page)
        os.chmod(handle.name, 0o644)
        os.replace(handle.name, output)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return output
