#!/usr/bin/env python3
"""
mailsec.py - Mail security posture checker for a domain.

Checks SPF, DMARC, and common DKIM selectors. Grades findings and
prints a coloured report with remediation advice and validation commands.
"""

import argparse
import re
import sys
from typing import Optional, Sequence

import dns.resolver
import dns.exception
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


class DNSLookupError(RuntimeError):
    """A DNS lookup failed transiently, so absence cannot be concluded."""


def safe_output(value: object) -> str:
    """Make untrusted DNS/error text inert before writing it to a terminal."""
    return "".join(
        character
        if ord(character) >= 32 and ord(character) != 127
        else f"\\x{ord(character):02x}"
        for character in str(value)
    )


# --- DNS helpers -------------------------------------------------------------

def _resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout = timeout
    return r


def txt_lookup(name: str) -> list[str]:
    """Return TXT records for a name, or [] only when the name/data is absent."""
    try:
        answers = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        raise DNSLookupError(f"TXT lookup for {name} failed: {exc}") from exc
    out = []
    for rdata in answers:
        # TXT records can be split into multiple strings; concatenate.
        out.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
    return out


def parse_tag_list(record: str) -> dict[str, str]:
    """Parse a semicolon-delimited DNS tag list without hiding duplicates."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        if key in tags:
            raise ValueError(f"duplicate {key}= tag")
        tags[key] = value.strip()
    return tags


def normalize_domain(value: str) -> str:
    """Return a safe ASCII DNS name suitable for lookups and shell examples."""
    value = value.strip().rstrip(".")
    try:
        ascii_domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError("domain is not valid IDNA") from exc

    if not ascii_domain or len(ascii_domain) > 253:
        raise argparse.ArgumentTypeError("domain must contain 1 to 253 characters")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise argparse.ArgumentTypeError(
            "enter a DNS domain such as example.com (not a URL or email address)"
        )
    return ascii_domain


def normalize_selector(value: str) -> str:
    """Constrain selectors before using them in DNS names and shell examples."""
    value = value.strip().lower()
    if not value or len(value) > 253 or not re.fullmatch(
        r"[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?", value
    ):
        raise argparse.ArgumentTypeError("DKIM selector contains invalid characters")
    return value


# --- SPF analysis ------------------------------------------------------------

def analyse_spf(domain: str) -> dict:
    records = txt_lookup(domain)
    spf_records = [
        record for record in records
        if record.lower() == "v=spf1" or record.lower().startswith("v=spf1 ")
    ]
    spf = spf_records[0] if len(spf_records) == 1 else None

    result = {
        "record": spf,
        "all_qualifier": None,
        "direct_lookup_terms": 0,
        "issues": [],
        "grade": "FAIL",
        "remediation": [],
        "validate": [],
    }

    if len(spf_records) > 1:
        result["record"] = " | ".join(spf_records)
        result["issues"].append(
            f"Multiple SPF records are published ({len(spf_records)}). This causes "
            "SPF PermError; combine them into one record."
        )
        result["remediation"].append(
            "Merge every legitimate sender into one v=spf1 record and remove the others."
        )
        result["validate"].append(f"dig TXT {domain}")
        return result

    if not spf:
        result["issues"].append("No SPF record published.")
        result["grade"] = "FAIL"
        result["remediation"].append(
            f"Publish an SPF record for {domain} that ends in -all "
            f"after listing all legitimate senders (MX, A, includes)."
        )
        result["validate"].append(
            f"dig TXT {domain}"
        )
        return result

    # SPF is ordered. Evaluate the first all mechanism and flag unreachable terms.
    terms = spf.split()[1:]
    all_index = None
    for index, term in enumerate(terms):
        match = re.fullmatch(r"([+?~-]?)all", term, flags=re.IGNORECASE)
        if match:
            all_index = index
            qualifier = match.group(1) or "+"
            result["all_qualifier"] = f"{qualifier}all"
            break

    qualifier = result["all_qualifier"]
    if qualifier == "-all":
        result["grade"] = "PASS"
    elif qualifier == "~all":
        result["grade"] = "WARN"
        result["issues"].append(
            "SPF ends in ~all, returning SoftFail rather than Fail for an "
            "unauthorised envelope sender."
        )
        result["remediation"].append(
            "Consider tightening to -all once you have verified all legitimate "
            "senders are covered."
        )
    elif qualifier == "?all":
        result["grade"] = "FAIL"
        result["issues"].append(
            "SPF ends in ?all (Neutral), making no assertion about unmatched "
            "envelope senders."
        )
        result["remediation"].append(
            "Change ?all to -all. Validate that MX, A, and all include: mechanisms "
            "cover every legitimate sender first."
        )
    elif qualifier == "+all":
        result["grade"] = "FAIL"
        result["issues"].append(
            "SPF ends in +all (Pass All). This authorises every sender on the "
            "internet — effectively no policy."
        )
        result["remediation"].append(
            "Replace +all with -all immediately."
        )
    elif any(term.lower().startswith("redirect=") for term in terms):
        result["grade"] = "WARN"
        result["issues"].append(
            "SPF uses redirect=. Its final policy depends on the redirected record "
            "and is not resolved by this static check."
        )
        result["remediation"].append(
            "Validate the complete redirected SPF evaluation with an SPF evaluator."
        )
    else:
        result["issues"].append(
            "SPF has no all mechanism or redirect, so unmatched envelope senders "
            "produce an implicit Neutral result."
        )
        result["remediation"].append(
            "Add an explicit '-all' mechanism at the end of the SPF record."
        )

    if all_index is not None and all_index < len(terms) - 1:
        result["issues"].append(
            "Terms appear after the all mechanism and are unreachable during SPF evaluation."
        )
        if result["grade"] == "PASS":
            result["grade"] = "WARN"

    # This is the direct count. include/redirect targets can add further lookups.
    lookup_names = {"include", "a", "mx", "ptr", "exists"}
    lookup_terms = 0
    for term in terms:
        unqualified = term[1:] if term[:1] in "+-?~" else term
        mechanism = re.split(r"[:/=]", unqualified, maxsplit=1)[0].lower()
        if mechanism in lookup_names or unqualified.lower().startswith("redirect="):
            lookup_terms += 1
    result["direct_lookup_terms"] = lookup_terms
    if lookup_terms > 10:
        result["issues"].append(
            f"SPF contains {lookup_terms} direct DNS-lookup terms (RFC 7208 limit is "
            "10). This causes PermError before recursive includes are even counted."
        )
        result["grade"] = "FAIL"
    if any(
        re.split(r"[:/=]", term[1:] if term[:1] in "+-?~" else term, maxsplit=1)[0].lower()
        == "ptr"
        for term in terms
    ):
        result["issues"].append("SPF uses the deprecated ptr mechanism.")
        if result["grade"] == "PASS":
            result["grade"] = "WARN"
        result["remediation"].append(
            "Replace ptr with explicit ip4/ip6 mechanisms or a maintained include."
        )

    result["validate"].append(f"dig TXT {domain}")
    result["validate"].append(
        f"swaks --to your-test@example.com --from test@{domain} "
        f"--server <your-smtp>:587 --tls  (inspect Authentication-Results)"
    )
    return result


# --- DMARC analysis ----------------------------------------------------------

def analyse_dmarc(domain: str) -> dict:
    name = f"_dmarc.{domain}"
    records = txt_lookup(name)
    dmarc_records = [
        record for record in records
        if record.split(";", 1)[0].strip() == "v=DMARC1"
    ]
    dmarc = dmarc_records[0] if len(dmarc_records) == 1 else None

    result = {
        "record": dmarc,
        "policy": None,
        "subdomain_policy": None,
        "nonexistent_policy": None,
        "test_mode": "n",
        "effective_policy": None,
        "issues": [],
        "grade": "FAIL",
        "remediation": [],
        "validate": [f"dig TXT _dmarc.{domain}"],
    }

    if len(dmarc_records) > 1:
        result["record"] = " | ".join(dmarc_records)
        result["issues"].append(
            f"Multiple DMARC records are published ({len(dmarc_records)}). Receivers "
            "discard all of them, so no DMARC policy is applied."
        )
        result["remediation"].append(
            "Merge the policy and reporting destinations into one DMARC record."
        )
        return result

    if not dmarc:
        result["issues"].append("No DMARC record published.")
        result["remediation"].append(
            f"Publish a DMARC record at _dmarc.{domain}. Start with p=none and rua= "
            "reporting, remediate unaligned mail, then choose an enforcement policy "
            "appropriate for the domain's mail flows."
        )
        return result

    try:
        tags = parse_tag_list(dmarc)
    except ValueError as exc:
        result["issues"].append(f"Invalid DMARC record: {exc}.")
        result["remediation"].append("Remove duplicate tags from the DMARC record.")
        return result

    result["policy"] = tags.get("p", "none").lower()
    result["subdomain_policy"] = tags.get("sp", result["policy"]).lower()
    result["nonexistent_policy"] = tags.get(
        "np", result["subdomain_policy"]
    ).lower()
    result["test_mode"] = tags.get("t", "n").lower()

    p = result["policy"]
    valid_policies = {"none", "quarantine", "reject"}
    if "p" not in tags:
        result["issues"].append(
            "No p= tag; current DMARC rules treat the policy as p=none."
        )

    if p not in valid_policies:
        result["issues"].append(
            f"DMARC policy 'p={p}' is not a valid enforcement level."
        )
        result["remediation"].append("Set p=none, p=quarantine, or p=reject.")
        return result

    invalid_secondary = [
        f"{tag}={tags[tag]}"
        for tag in ("sp", "np")
        if tag in tags and tags[tag].lower() not in valid_policies
    ]
    if invalid_secondary:
        result["issues"].append(
            "Invalid DMARC subdomain policy: " + ", ".join(invalid_secondary) + "."
        )
        result["remediation"].append("Use none, quarantine, or reject for sp= and np=.")
        return result

    if result["test_mode"] not in {"y", "n"}:
        result["issues"].append(
            f"Invalid DMARC test-mode value t={result['test_mode']}."
        )
        result["remediation"].append("Use t=y for testing or t=n for enforcement.")
        return result

    # RFC 9989 test mode lowers the applied policy by one level.
    effective = p
    if result["test_mode"] == "y":
        effective = {"reject": "quarantine", "quarantine": "none", "none": "none"}[p]
        result["issues"].append(
            f"DMARC test mode is enabled (t=y), so p={p} is effectively {effective}."
        )
    result["effective_policy"] = effective

    if effective == "reject":
        result["grade"] = "PASS"
    elif effective == "quarantine":
        result["grade"] = "WARN"
        result["issues"].append(
            "The effective DMARC policy is quarantine. Receivers treat failures as "
            "suspicious but retain local handling discretion."
        )
        result["remediation"].append(
            "After analysing aggregate reports and validating aligned DKIM for indirect "
            "mail flows, decide whether reject is appropriate for this domain."
        )
    else:
        result["grade"] = "FAIL"
        result["issues"].append(
            "The effective DMARC policy is none. The domain requests no special "
            "handling for authentication failures."
        )
        result["remediation"].append(
            "Use aggregate reports to remediate legitimate unaligned mail, then move "
            "to an enforcement policy appropriate for the domain's mail flows."
        )

    policy_rank = {"none": 0, "quarantine": 1, "reject": 2}
    weaker_scopes = [
        f"sp={result['subdomain_policy']}" if "sp" in tags else None,
        f"np={result['nonexistent_policy']}" if "np" in tags else None,
    ]
    weaker_scopes = [
        item for item in weaker_scopes
        if item and policy_rank[item.split("=", 1)[1]] < policy_rank[p]
    ]
    if weaker_scopes:
        result["issues"].append(
            "Weaker policy creates subdomain impersonation exposure: "
            + ", ".join(weaker_scopes) + "."
        )
        if result["grade"] == "PASS":
            result["grade"] = "WARN"
        result["remediation"].append(
            "Align sp=/np= with p= unless the weaker subdomain policy is intentional."
        )

    if "pct" in tags:
        result["issues"].append(
            "pct= is obsolete in RFC 9989; mixed receiver implementations may handle "
            "this legacy tag inconsistently. Use t=y/t=n for policy testing."
        )
        if tags["pct"] != "100" and result["grade"] == "PASS":
            result["grade"] = "WARN"

    # rua sanity.
    if "rua" not in tags:
        result["issues"].append(
            "No rua= tag. DMARC aggregate reports are not being collected, so "
            "you have no visibility into who is sending as your domain."
        )
        result["remediation"].append(
            "Add rua=mailto:dmarc-reports@yourdomain to receive aggregate reports."
        )

    return result


# --- DKIM analysis -----------------------------------------------------------

COMMON_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "s1", "s2",
    "mail", "dkim", "hosth", "mandrill", "smtp", "mandrillapp",
]


def analyse_dkim(domain: str, selectors: Optional[Sequence[str]] = None) -> dict:
    selectors_to_check = list(selectors) if selectors else COMMON_SELECTORS
    selectors_are_authoritative = bool(selectors)
    result = {
        "found": [],
        "invalid": [],
        "revoked": [],
        "selectors_checked": selectors_to_check,
        "selectors_are_authoritative": selectors_are_authoritative,
        "issues": [],
        "notes": [],
        "grade": "PASS",
        "remediation": [],
        "validate": [],
    }

    for sel in selectors_to_check:
        name = f"{sel}._domainkey.{domain}"
        recs = txt_lookup(name)
        for rec in recs:
            try:
                tags = parse_tag_list(rec)
            except ValueError as exc:
                reason = f"{exc}: {rec}"
                if not any(item[1] == reason for item in result["invalid"]):
                    result["invalid"].append((sel, reason))
                continue
            # v= is recommended, not required, for a DKIM public-key record.
            if tags.get("v", "DKIM1") != "DKIM1" or "p" not in tags:
                continue
            if not tags["p"]:
                reason = "revoked key response (empty p=; possibly a wildcard record)"
                if not any(item[1] == reason for item in result["revoked"]):
                    result["revoked"].append((sel, reason))
                continue
            if not any(item[1] == rec for item in result["found"]):
                result["found"].append((sel, rec))

    if not result["found"]:
        if selectors_are_authoritative:
            result["grade"] = "FAIL"
            result["issues"].append(
                "No usable DKIM public key was found for the supplied selector(s)."
            )
            result["remediation"].append(
                "Publish a non-revoked public key for each active selector, or rotate "
                "the sender to a selector that has a valid key."
            )
        else:
            result["grade"] = "WARN"
            result["issues"].append(
                "No DKIM key was found at the probed common selectors. This is "
                "inconclusive because DKIM selectors cannot be enumerated through DNS."
            )
            result["remediation"].append(
                "Inspect a real message's DKIM-Signature header and rerun with each "
                "s= selector. Confirm that its d= domain aligns with the From domain."
            )

    if result["found"]:
        result["notes"].append(
            "Published keys do not prove that outbound messages are signed or DMARC-"
            "aligned; verify DKIM-Signature and Authentication-Results on real mail."
        )

    if result["revoked"]:
        result["notes"].append(
            f"Observed {len(result['revoked'])} distinct revoked DKIM key response(s); "
            "a wildcard record can answer multiple selector probes."
        )

    if result["invalid"]:
        result["issues"].append(
            f"Observed {len(result['invalid'])} distinct malformed DKIM key response(s)."
        )
        if result["grade"] == "PASS":
            result["grade"] = "WARN"

    result["validate"] = (
        [f"dig TXT {selector}._domainkey.{domain}" for selector in selectors_to_check]
        if selectors_are_authoritative
        else [f"dig TXT <selector>._domainkey.{domain}"]
    )
    return result


# --- Rendering ---------------------------------------------------------------

GRADE_COLOUR = {
    "PASS": "bold green",
    "WARN": "bold yellow",
    "FAIL": "bold red",
}


def render_section(title: str, data: dict, extra_fields=None):
    colour = GRADE_COLOUR[data["grade"]]
    console.rule(f"[{colour}]{title} — {data['grade']}[/]")

    if data.get("record"):
        console.print(Panel(
            Text(safe_output(data["record"]), style="cyan", overflow="fold"),
            title="Record", border_style="dim", box=box.SQUARE,
        ))
    if extra_fields:
        for k, v in extra_fields:
            if v:
                console.print(f"  [dim]{k}:[/] {escape(safe_output(v))}")

    if data.get("issues"):
        console.print("\n[bold red]Issues[/]")
        for i in data["issues"]:
            console.print(f"  [red]✗[/] {escape(safe_output(i))}")

    if data.get("remediation"):
        console.print("\n[bold yellow]Remediation[/]")
        for r in data["remediation"]:
            console.print(f"  [yellow]→[/] {escape(safe_output(r))}")

    if data.get("validate"):
        console.print("\n[bold blue]Validate[/]")
        for v in data["validate"]:
            console.print(f"  [blue]$[/] {escape(safe_output(v))}")

    console.print()


def render_overall(domain: str, spf: dict, dmarc: dict, dkim: dict):
    table = Table(
        title=f"Summary for {domain}",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Control", style="bold")
    table.add_column("Grade", justify="center")
    table.add_column("Key finding")

    def row(name, data):
        colour = GRADE_COLOUR[data["grade"]]
        finding = data["issues"][0] if data["issues"] else "No issues detected."
        # Truncate for table width.
        if len(finding) > 80:
            finding = finding[:77] + "..."
        table.add_row(
            name, f"[{colour}]{data['grade']}[/]", escape(safe_output(finding))
        )

    row("SPF", spf)
    row("DMARC", dmarc)
    row("DKIM", dkim)

    console.print(table)
    console.print()

    # DMARC policy is what addresses direct RFC5322.From-domain impersonation.
    if dmarc["grade"] == "FAIL":
        verdict = (
            "[bold red]Direct-domain impersonation exposure.[/] The effective "
            "DMARC policy does not request enforcement for messages that fail "
            f"authentication and alignment as @{domain}."
        )
        box_style = "bold red"
    elif dmarc["grade"] == "WARN":
        verdict = (
            "[bold yellow]Partial direct-domain protection.[/] DMARC is present, "
            "but its effective or subdomain policy leaves a weaker impersonation path."
        )
        box_style = "bold yellow"
    else:
        verdict = (
            "[bold green]DMARC enforcement is published.[/] This reduces direct-domain "
            "spoofing but does not cover lookalike/display-name attacks, compromised "
            "accounts, or abuse through an over-broad authorized sender."
        )
        box_style = "bold green"

    console.print(Panel(verdict, border_style=box_style, box=box.HEAVY))


# --- Main --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Check SPF, DMARC, and DKIM posture for a domain.",
    )
    parser.add_argument(
        "domain",
        type=normalize_domain,
        help="Organizational/author domain to inspect, e.g. example.com",
    )
    parser.add_argument(
        "--selector",
        dest="selectors",
        action="append",
        type=normalize_selector,
        help=(
            "Known DKIM selector from a DKIM-Signature s= value; repeat for multiple "
            "selectors. Without this option, common names are probed inconclusively."
        ),
    )
    args = parser.parse_args()
    domain = args.domain

    console.print()
    console.print(Panel.fit(
        f"[bold]Mail Security Posture Check[/] — [cyan]{domain}[/]",
        border_style="cyan",
    ))
    console.print()

    try:
        with console.status("[cyan]Querying DNS...[/]"):
            spf = analyse_spf(domain)
            dmarc = analyse_dmarc(domain)
            dkim = analyse_dkim(domain, args.selectors)
    except DNSLookupError as exc:
        console.print(f"[bold red]DNS lookup failed:[/] {escape(safe_output(exc))}")
        console.print("The audit is inconclusive; retry when DNS is reachable.")
        sys.exit(3)

    render_section("SPF", spf, extra_fields=[
        ("all qualifier", spf.get("all_qualifier")),
        ("direct DNS lookup terms", spf.get("direct_lookup_terms")),
    ])
    render_section("DMARC", dmarc, extra_fields=[
        ("policy", dmarc.get("policy")),
        ("effective policy", dmarc.get("effective_policy")),
        ("subdomain policy", dmarc.get("subdomain_policy")),
        ("non-existent subdomain policy", dmarc.get("nonexistent_policy")),
        ("test mode", dmarc.get("test_mode")),
    ])

    # DKIM has a slightly different shape — render inline.
    colour = GRADE_COLOUR[dkim["grade"]]
    console.rule(f"[{colour}]DKIM — {dkim['grade']}[/]")
    if dkim["found"]:
        for sel, rec in dkim["found"]:
            console.print(
                f"  [green]✓[/] selector [bold]{escape(safe_output(sel))}[/]: "
                f"{escape(safe_output(rec[:80]))}..."
            )
    if dkim["invalid"]:
        for sel, reason in dkim["invalid"]:
            console.print(
                f"  [red]✗[/] selector [bold]{escape(safe_output(sel))}[/]: "
                f"{escape(safe_output(reason[:100]))}"
            )
    if dkim["revoked"]:
        for sel, reason in dkim["revoked"]:
            console.print(
                f"  [yellow]○[/] selector [bold]{escape(safe_output(sel))}[/]: "
                f"{escape(safe_output(reason[:100]))}"
            )
    if dkim["issues"]:
        console.print("\n[bold red]Issues[/]")
        for i in dkim["issues"]:
            console.print(f"  [red]✗[/] {escape(safe_output(i))}")
    if dkim["notes"]:
        console.print("\n[bold cyan]Scope note[/]")
        for note in dkim["notes"]:
            console.print(f"  [cyan]•[/] {escape(safe_output(note))}")
    if dkim["remediation"]:
        console.print("\n[bold yellow]Remediation[/]")
        for r in dkim["remediation"]:
            console.print(f"  [yellow]→[/] {escape(safe_output(r))}")
    if dkim["validate"]:
        console.print("\n[bold blue]Validate[/]")
        for v in dkim["validate"]:
            console.print(f"  [blue]$[/] {escape(safe_output(v))}")
    console.print()

    render_overall(domain, spf, dmarc, dkim)

    # Exit code: non-zero if any FAIL, useful for CI.
    if any(d["grade"] == "FAIL" for d in (spf, dmarc, dkim)):
        sys.exit(2)
    if any(d["grade"] == "WARN" for d in (spf, dmarc, dkim)):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
