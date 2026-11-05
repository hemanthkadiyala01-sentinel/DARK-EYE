"""
DARK-EYE M7.5 command-line entry point.

Usage:
    python -m backend.security_research.cli https://TARGET
"""

import argparse
from .agent import SecurityResearchAgent, save_report


def main():
    parser = argparse.ArgumentParser(
        description="DARK-EYE authorized security research MVP"
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

    args = parser.parse_args()

    print()
    print("==============================================")
    print(" DARK-EYE SECURITY RESEARCH AGENT - M7.5")
    print("==============================================")
    print()

    print(f"[+] Target: {args.target}")
    print(f"[+] Allowed domains: {', '.join(args.domain)}")
    print()

    try:
        agent = SecurityResearchAgent(
            target=args.target,
            allowed_domains=args.domain,
        )

        print("[+] Verifying scope...")
        agent.verify_scope()
        print("[OK] Target is inside configured scope.")
        print()

        print("[+] Performing passive HTTP research...")
        result = agent.run()

        print("[OK] Research complete.")
        print()

        findings = result["findings"]

        print(f"[+] Findings generated: {len(findings)}")
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
