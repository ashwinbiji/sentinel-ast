import argparse
import json
import os
import sys
import difflib
import libcst as cst

# Import internal scanning logic
from parser_engine import run_parser
from cst_remediator import SecurityTransformer, ImportFixer

# ANSI Colors for terminal output
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def generate_sarif(vulnerabilities, target_file):
    """Generates OASIS SARIF v2.1.0 compliant JSON report."""
    results = []
    for vuln in vulnerabilities:
        results.append({
            "ruleId": vuln.get("type", "SECURITY_ISSUE"),
            "level": "error",
            "message": {
                "text": vuln.get("message", "Security vulnerability detected.")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_file
                    },
                    "region": {
                        "startLine": vuln.get("line", 1)
                    }
                }
            }]
        })

    sarif_structure = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sentinel",
                    "version": "1.0.0",
                    "rules": [
                        {"id": "EVAL_USAGE", "shortDescription": {"text": "Arbitrary Code Execution via eval()"}},
                        {"id": "COMMAND_INJECTION", "shortDescription": {"text": "OS Command Injection via system/subprocess"}}
                    ]
                }
            },
            "results": results
        }]
    }
    return json.dumps(sarif_structure, indent=2)

def generate_diff(target_file):
    """Generates a colorized Unified Diff preview without modifying files."""
    try:
        with open(target_file, "r") as f:
            original_code = f.read()

        tree = cst.parse_module(original_code)
        patched_tree = tree.visit(SecurityTransformer()).visit(ImportFixer())
        modified_code = patched_tree.code

        diff = difflib.unified_diff(
            original_code.splitlines(keepends=True),
            modified_code.splitlines(keepends=True),
            fromfile=f"a/{target_file}",
            tofile=f"b/{target_file}"
        )

        diff_lines = list(diff)
        if not diff_lines:
            return f"{Colors.GREEN}No remediation changes required.{Colors.RESET}"

        colored_diff = []
        for line in diff_lines:
            if line.startswith('+'):
                colored_diff.append(f"{Colors.GREEN}{line}{Colors.RESET}")
            elif line.startswith('-'):
                colored_diff.append(f"{Colors.RED}{line}{Colors.RESET}")
            elif line.startswith('@'):
                colored_diff.append(f"{Colors.CYAN}{line}{Colors.RESET}")
            else:
                colored_diff.append(line)

        return "".join(colored_diff)

    except Exception as e:
        return f"{Colors.RED}Error generating diff: {str(e)}{Colors.RESET}"

def apply_auto_fix(target_file):
    """Applies LibCST security transformers directly to disk."""
    try:
        with open(target_file, "r") as f:
            original_code = f.read()

        tree = cst.parse_module(original_code)
        patched_tree = tree.visit(SecurityTransformer()).visit(ImportFixer())

        with open(target_file, "w") as f:
            f.write(patched_tree.code)

        print(f"{Colors.GREEN}[+] Successfully applied secure patches to '{target_file}'.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to apply auto-fix: {str(e)}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel SAST & Automated Program Repair Platform"
    )
    parser.add_argument("target", help="Path to Python source file to scan")
    parser.add_argument("--diff", action="store_true", help="Display git-style unified diff of suggested security patches")
    parser.add_argument("--apply", action="store_true", help="Overwrite target file with secure code fixes")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format (default: text)")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"{Colors.RED}Error: File '{args.target}' does not exist.{Colors.RESET}")
        sys.exit(1)

    # 1. Execute AST Scan
    vulns = run_parser(args.target)

    # 2. Output Handling
    if args.format == "sarif":
        print(generate_sarif(vulns, args.target))
        sys.exit(0)
    elif args.format == "json":
        print(json.dumps(vulns, indent=2))
        sys.exit(0)

    # Standard Terminal Report
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- SENTINEL SAST REPORT ---{Colors.RESET}")
    print(f"Target File: {args.target}")
    print(f"Vulnerabilities Found: {len(vulns)}\n")

    for v in vulns:
        if "error" in v:
            print(f"{Colors.RED}Parser Error: {v['error']}{Colors.RESET}")
            continue
        print(f" • Line {v['line']}: [{v['type']}] {v['message']}")

    # 3. Dry-Run Diff Preview
    if args.diff:
        print(f"\n{Colors.BOLD}--- SUGGESTED REMEDIATION DIFF ---{Colors.RESET}")
        print(generate_diff(args.target))

    # 4. In-Place Auto-Fixing
    if args.apply:
        print(f"\n{Colors.BOLD}--- APPLYING AUTO-FIX ---{Colors.RESET}")
        apply_auto_fix(args.target)

if __name__ == "__main__":
    main()