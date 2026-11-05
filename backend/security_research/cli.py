"""
DARK-EYE M7.7 command-line entry point.

Usage:
    python -m backend.security_research.cli https://TARGET --domain DOMAIN [--authorized]
"""

import argparse
from .agent import (
    SecurityResearchAgent,
    save_report,
    AuthorizationStatus,
    PermissionGrant,
    ProgramMetadata,
)


def main():
    parser = argparse.ArgumentParser(
        description="DARK-EYE authorized security research MVP (M7.7)"
    )

    parser.add_argument(
        "target",
        help="Authorized target URL"
    )

    parser.add_argument(
        "--domain",
        required=True,
        action="append",
        help="Allowed root domain. Can be supplied multiple times."
    )

    parser.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="Explicitly confirm authorization to perform passive security research on this target."
    )

    parser.add_argument(
        "--authorized-by",
        default="cli-operator",
        help="Name or role of the authorizing entity."
    )

    parser.add_argument(
        "--program",
        default="cli-engagement",
        help="Program or engagement identifier."
    )

    args = parser.parse_args()

    print()
    print("==============================================")
    print(" DARK-EYE SECURITY RESEARCH AGENT - M7.7")
    print("==============================================")
    print()

    print(f"[+] Target: {args.target}")
    print(f"[+] Allowed domains: {', '.join(args.domain)}")
    print(f"[+] Program ID: {args.program}")
    print(f"[+] Authorized flag provided: {args.authorized}")
    print()

    try:
        permission_status = (
            AuthorizationStatus.AUTHORIZED
            if args.authorized
            else AuthorizationStatus.UNAUTHORIZED
        )
        permission = PermissionGrant(
            status=permission_status,
            authorized_by=args.authorized_by,
            scope_reference=args.program,
        )
        program = ProgramMetadata(
            program_id=args.program,
            allowed_domains=args.domain,
        )

        agent = SecurityResearchAgent(
            target=args.target,
            allowed_domains=args.domain,
            permission=permission,
            program=program,
        )

        print("[+] Verifying scope...")
        agent.verify_scope()
        print("[OK] Target is inside configured scope.")
        print()

        print("[+] Verifying authorization...")
        agent.verify_authorization()
        print("[OK] Explicit authorization grant verified.")
        print()

        print("[+] Performing passive HTTP research...")
        result = agent.run()

        print("[OK] Research complete.")
        print()

        findings = result["findings"]
        evidence = result["evidence"]

        print(f"[+] Findings generated: {len(findings)}")
        print(f"[+] Endpoints cataloged: {len(evidence.get('endpoints', []))}")
        if evidence.get("sha256_digest"):
            print(f"[+] Response SHA-256: {evidence['sha256_digest']}")
        print()

        for number, finding in enumerate(findings, 1):
            val_status = ""
            if "validation" in finding and isinstance(finding["validation"], dict):
                v_stat = finding["validation"].get("status")
                if v_stat:
                    val_status = f" | {v_stat}"

            print(
                f"{number}. "
                f"{finding['title']} | "
                f"{finding['severity']} | "
                f"{finding['confidence']}%"
                f"{val_status}"
            )

        print()

        json_path, md_path = save_report(result)

        print(f"[+] Evidence: {json_path}")
        print(f"[+] Report:   {md_path}")
        print()

    except PermissionError as exc:
        print(f"[BLOCKED] {exc}")

    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
