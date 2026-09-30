import ast
import sys
import json
import os

class AdvancedSecurityScanner(ast.NodeVisitor):
    def __init__(self, source_lines):
        self.vulnerabilities = []
        self.source_lines = source_lines

    def _get_line_snippet(self, lineno):
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return "N/A"

    def visit_Call(self, node):
        # 1. Detect eval() usage
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.vulnerabilities.append({
                "type": "EVAL_USAGE",
                "line": node.lineno,
                "code_snippet": self._get_line_snippet(node.lineno),
                "message": "Dangerous eval() function detected with string execution risk."
            })

        # 2. Detect os.system() and subprocess(..., shell=True)
        if isinstance(node.func, ast.Attribute):
            # os.system()
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                self.vulnerabilities.append({
                    "type": "COMMAND_INJECTION",
                    "line": node.lineno,
                    "code_snippet": self._get_line_snippet(node.lineno),
                    "message": "Use of os.system() detected. Susceptible to OS command injection."
                })
            
            # pickle.loads() or pickle.load()
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle' and node.func.attr in ['loads', 'load']:
                self.vulnerabilities.append({
                    "type": "INSECURE_DESERIALIZATION",
                    "line": node.lineno,
                    "code_snippet": self._get_line_snippet(node.lineno),
                    "message": "Untrusted pickle deserialization detected."
                })

            # hashlib.md5() or hashlib.sha1()
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib' and node.func.attr in ['md5', 'sha1']:
                self.vulnerabilities.append({
                    "type": "WEAK_CRYPTO",
                    "line": node.lineno,
                    "code_snippet": self._get_line_snippet(node.lineno),
                    "message": f"Cryptographically weak hash function hashlib.{node.func.attr}() used."
                })

            # random.randint(), random.choice(), random.random()
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == 'random':
                self.vulnerabilities.append({
                    "type": "WEAK_RANDOM",
                    "line": node.lineno,
                    "code_snippet": self._get_line_snippet(node.lineno),
                    "message": "Standard pseudo-random generator 'random' used for potential security context."
                })

            # SQL Injection via cursor.execute() with string formatting
            elif node.func.attr == 'execute':
                if node.args:
                    first_arg = node.args[0]
                    # Detect f-strings (JoinedStr), % formatting (BinOp Mod), or .format()
                    is_fstring = isinstance(first_arg, ast.JoinedStr)
                    is_percent_fmt = isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod)
                    is_dot_format = isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format'

                    if is_fstring or is_percent_fmt or is_dot_format:
                        self.vulnerabilities.append({
                            "type": "SQL_INJECTION",
                            "line": node.lineno,
                            "code_snippet": self._get_line_snippet(node.lineno),
                            "message": "SQL query built using dynamic string formatting instead of parameterized bindings."
                        })

        # Detect subprocess calls with shell=True
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.vulnerabilities.append({
                        "type": "COMMAND_INJECTION",
                        "line": node.lineno,
                        "code_snippet": self._get_line_snippet(node.lineno),
                        "message": "subprocess call executed with shell=True."
                    })

        self.generic_visit(node)

    def visit_Assign(self, node):
        # 3. Detect Hardcoded Secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                variable_name = target.id.upper()
                secret_keywords = ['API_KEY', 'PASSWORD', 'SECRET_KEY', 'TOKEN', 'PRIVATE_KEY', 'ACCESS_TOKEN']
                
                if any(keyword in variable_name for keyword in secret_keywords):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # Filter out empty strings or placeholders
                        val = node.value.value.strip()
                        if val and not val.startswith("YOUR_") and not val == "ENV":
                            self.vulnerabilities.append({
                                "type": "HARDCODED_SECRET",
                                "line": node.lineno,
                                "code_snippet": self._get_line_snippet(node.lineno),
                                "message": f"Hardcoded secret string assigned to variable '{target.id}'."
                            })
        self.generic_visit(node)

def run_parser(file_path):
    if not os.path.exists(file_path):
        return [{"error": f"Target file '{file_path}' does not exist."}]

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
            source_lines = source_code.splitlines()

        tree = ast.parse(source_code, filename=file_path)
        scanner = AdvancedSecurityScanner(source_lines)
        scanner.visit(tree)
        return scanner.vulnerabilities

    except SyntaxError as e:
        return [{"error": f"Syntax error in '{file_path}' at line {e.lineno}: {e.msg}"}]
    except Exception as e:
        return [{"error": f"Unexpected parsing error: {str(e)}"}]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps([{"error": "Usage: python3 parser_engine.py <target_file.py>"}]))
        sys.exit(1)

    target_file = sys.argv[1]
    results = run_parser(target_file)
    print(json.dumps(results))