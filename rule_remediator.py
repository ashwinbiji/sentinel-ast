import sys
import json
import os

# ANSI Terminal Color Codes (100% portable, no external pip dependencies)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def load_rules(filepath="rules.json"):
    if not os.path.exists(filepath):
        print(f"{Colors.RED}[!] Error: Rules database file '{filepath}' not found.{Colors.RESET}")
        sys.exit(1)
    try:
        with open(filepath, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"{Colors.RED}[!] Error: Failed to parse '{filepath}'. Invalid JSON structure.{Colors.RESET}")
        sys.exit(1)

def get_severity_badge(severity):
    severity = severity.upper()
    if severity == "CRITICAL":
        return f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.RESET}"
    elif severity == "HIGH":
        return f"{Colors.RED}[HIGH]{Colors.RESET}"
    elif severity == "MEDIUM":
        return f"{Colors.YELLOW}[MEDIUM]{Colors.RESET}"
    return f"{Colors.BLUE}[LOW]{Colors.RESET}"

def process_remediation(vuln_list, rules_db):
    total_findings = len(vuln_list)
    remediated_count = 0
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}========================================================")
    print(f"       SENTINEL SAST REMEDIATION ENGINE (OFFLINE)      ")
    print(f"========================================================{Colors.RESET}\n")
    print(f"Total AST Findings Detected: {Colors.BOLD}{total_findings}{Colors.RESET}\n")

    for idx, vuln in enumerate(vuln_list, 1):
        vuln_type = vuln.get("type") or vuln.get("vulnerability_type", "UNKNOWN")
        line_no = vuln.get("line", "N/A")
        parser_msg = vuln.get("message", "No description provided by parser.")
        
        print(f"{Colors.BOLD}Finding #{idx}:{Colors.RESET} Type: {Colors.UNDERLINE}{vuln_type}{Colors.RESET} | Line: {line_no}")
        
        if vuln_type in rules_db:
            rule = rules_db[vuln_type]
            badge = get_severity_badge(rule.get("severity", "LOW"))
            remediated_count += 1
            
            print(f"Status:   {Colors.GREEN}REMEDIATED{Colors.RESET}")
            print(f"Severity: {badge} | CWE: {Colors.BOLD}{rule.get('cwe', 'N/A')}{Colors.RESET} - {rule.get('title', '')}")
            print(f"Context:  {parser_msg}")
            print(f"Details:  {rule.get('description', '')}")
            print(f"\n{Colors.BOLD}Suggested Secure Patch:{Colors.RESET}")
            print(f"{Colors.GREEN}--------------------------------------------------------")
            print(f"{rule.get('fix', '# No fix snippet available')}")
            print(f"--------------------------------------------------------{Colors.RESET}\n")
        else:
            print(f"Status:   {Colors.YELLOW}UNSUPPORTED RULE{Colors.RESET}")
            print(f"Context:  {parser_msg}")
            print(f"{Colors.YELLOW}No automated patch rule found in rules.json for '{vuln_type}'.{Colors.RESET}\n")
        
        print("-" * 56 + "\n")

    print(f"{Colors.BOLD}Execution Summary:{Colors.RESET}")
    print(f"  • Scanned Issues: {total_findings}")
    print(f"  • Successfully Remediated: {remediated_count}/{total_findings}")
    print(f"  • Unmatched Issues: {total_findings - remediated_count}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 rule_remediator.py '<vulnerability_json_string>'")
        sys.exit(1)
        
    rules = load_rules("rules.json")
    
    try:
        raw_input = sys.argv[1].strip()
        if not raw_input:
            print(f"{Colors.YELLOW}No AST vulnerabilities supplied to remediator.{Colors.RESET}")
            sys.exit(0)
            
        vuln_data = json.loads(raw_input)
        
        # Standardize single objects into an array
        if isinstance(vuln_data, dict):
            vuln_data = [vuln_data]
            
        if not isinstance(vuln_data, list) or len(vuln_data) == 0:
            print(f"{Colors.GREEN}Zero vulnerabilities detected. Code analysis passed clean.{Colors.RESET}")
            sys.exit(0)
            
        # Check for Phase 1 execution errors
        if "error" in vuln_data[0]:
            print(f"{Colors.RED}[!] Parser Error: {vuln_data[0]['error']}{Colors.RESET}")
            sys.exit(1)
            
        process_remediation(vuln_data, rules)
        
    except json.JSONDecodeError:
        print(f"{Colors.RED}[!] Error: Invalid JSON input received from Phase 1 parser.{Colors.RESET}")
        sys.exit(1)