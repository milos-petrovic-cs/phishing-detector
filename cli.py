#!/usr/bin/env python3

import argparse
import os
import sys
import json
from detector import analyze, DetectionResult

# Terminal colors

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def color_verdict(verdict: str) -> str:
    colors = {"PHISHING": C.RED, "SUSPICIOUS": C.YELLOW, "SAFE": C.GREEN}
    c = colors.get(verdict, "")
    return f"{c}{C.BOLD}{verdict}{C.RESET}"


def score_bar(score: float, width: int = 30) -> str:
    filled = round(score * width)
    empty = width - filled
    if score >= 0.55:
        color = C.RED
    elif score >= 0.25:
        color = C.YELLOW
    else:
        color = C.GREEN
    return f"{color}{'█' * filled}{C.DIM}{'░' * empty}{C.RESET}"


# Output formatter

def print_result(result: DetectionResult, json_output: bool = False):
    if json_output:
        out = {
            "url": result.url,
            "verdict": result.verdict,
            "risk_score": result.risk_percent,
            "flags": result.flags,
            "virustotal": result.virustotal,
        }
        print(json.dumps(out, indent=2))
        return

    print()
    print(f"  {C.BOLD}URL:{C.RESET}     {C.CYAN}{result.url}{C.RESET}")
    print(f"  {C.BOLD}Verdict:{C.RESET} {color_verdict(result.verdict)}")
    print(f"  {C.BOLD}Risk:{C.RESET}    {score_bar(result.score)}  {result.risk_percent}%")
    print()

    if result.flags:
        print(f"  {C.BOLD}Indicators:{C.RESET}")
        for flag in result.flags:
            print(f"    {C.YELLOW}⚠{C.RESET}  {flag}")
    else:
        print(f"  {C.GREEN}✓  No suspicious indicators found{C.RESET}")

    if result.virustotal:
        vt = result.virustotal
        print()
        print(f"  {C.BOLD}VirusTotal:{C.RESET}")
        if vt["status"] == "ok":
            vt_color = C.RED if vt["vt_verdict"] == "MALICIOUS" else (C.YELLOW if vt["vt_verdict"] == "SUSPICIOUS" else C.GREEN)
            print(f"    Detection: {vt_color}{vt['detection_rate']} engines{C.RESET}")
            print(f"    Verdict:   {vt_color}{vt['vt_verdict']}{C.RESET}")
        else:
            print(f"    {C.DIM}{vt.get('message', 'Unknown error')}{C.RESET}")

    print()
    print(f"  {C.DIM}{'─' * 50}{C.RESET}")


def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║
  ██████╔╝███████║██║███████╗███████║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║
  ██║     ██║  ██║██║███████║██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝

  Phishing URL Detector{C.RESET}{C.DIM}  v1.0  |  github.com/yourname/phishing-detector{C.RESET}
""")


# Entry point

def main():
    parser = argparse.ArgumentParser(
        description="Analyze URLs for phishing indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py https://paypal-secure-login.xyz/verify
  python cli.py https://google.com --vt-key YOUR_KEY
  python cli.py --batch urls.txt --json
  python cli.py https://bit.ly/3xAmPle --vt-key YOUR_KEY
        """
    )
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--vt-key", default=os.getenv("VT_API_KEY"), help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--batch", metavar="FILE", help="Text file with one URL per line")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--no-banner", action="store_true", help="Skip the ASCII banner")

    args = parser.parse_args()

    if not args.no_banner and not args.json:
        print_banner()

    if args.batch:
        try:
            with open(args.batch) as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"Error: file '{args.batch}' not found", file=sys.stderr)
            sys.exit(1)

        if not args.json:
            print(f"  Scanning {len(urls)} URLs...\n")

        results = []
        for url in urls:
            result = analyze(url, vt_api_key=args.vt_key)
            results.append(result)
            print_result(result, json_output=args.json)

        if not args.json:
            phishing = sum(1 for r in results if r.verdict == "PHISHING")
            suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
            safe = sum(1 for r in results if r.verdict == "SAFE")
            print(f"\n  {C.BOLD}Summary:{C.RESET} {C.RED}{phishing} phishing{C.RESET}  |  {C.YELLOW}{suspicious} suspicious{C.RESET}  |  {C.GREEN}{safe} safe{C.RESET}\n")

    elif args.url:
        result = analyze(args.url, vt_api_key=args.vt_key)
        print_result(result, json_output=args.json)

        # Exit code reflects verdict - useful for scripting/CI pipelines
        if result.verdict == "PHISHING":
            sys.exit(2)
        elif result.verdict == "SUSPICIOUS":
            sys.exit(1)
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
