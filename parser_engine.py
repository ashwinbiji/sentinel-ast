import ast
import sys
import json
import os

class TaintTracker(ast.NodeVisitor):
    def __init__(self, source_lines):
        self.vulnerabilities = []
        self.source_lines = source_lines
        self.tainted_vars = set()  

        # Sources of untrusted data
        self.sources = {'input', 'sys.argv'}
        
        # Sinks where tainted data causes execution vulnerabilities
        self.sinks = {'eval', 'os.system', 'subprocess.run'}

    def _get_snippet(self, lineno):
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return "N/A"

    def visit_Assign(self, node):
        """Track data propagation from untrusted sources into variables."""
        rhs_is_tainted = False

        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id in self.sources:
                rhs_is_tainted = True
            elif isinstance(node.value.func, ast.Attribute):
                attr_name = f"{getattr(node.value.func.value, 'id', '')}.{node.value.func.attr}"
                if attr_name in self.sources:
                    rhs_is_tainted = True
                    
        # Track propagation of an already tainted variable
        elif isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            rhs_is_tainted = True

        # If RHS is untrusted, mark all LHS assignment targets as tainted
        if rhs_is_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node):
        """Check if a dangerous sink receives a tainted variable."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"

        for arg in node.args:
            is_tainted_var = isinstance(arg, ast.Name) and arg.id in self.tainted_vars
            is_direct_source = isinstance(arg, ast.Call) and (
                (isinstance(arg.func, ast.Name) and arg.func.id in self.sources)
            )

            if func_name in self.sinks and (is_tainted_var or is_direct_source):
                var_str = arg.id if is_tainted_var else "direct input"
                self.vulnerabilities.append({
                    "type": "TAINT_PROPAGATION",
                    "line": node.lineno,
                    "code_snippet": self._get_snippet(node.lineno),
                    "message": f"Untrusted data from '{var_str}' flows into '{func_name}()'."
                })

        # Retain standard AST direct checks
        if func_name == "eval":
            self.vulnerabilities.append({
                "type": "EVAL_USAGE",
                "line": node.lineno,
                "code_snippet": self._get_snippet(node.lineno),
                "message": "Use of eval() detected."
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
        tracker = TaintTracker(source_lines)
        tracker.visit(tree)
        return tracker.vulnerabilities

    except SyntaxError as e:
        return [{"error": f"Syntax error in '{file_path}' at line {e.lineno}: {e.msg}"}]
    except Exception as e:
        return [{"error": f"Unexpected parsing error: {str(e)}"}]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps([{"error": "Usage: python3 parser_engine.py <target_file.py>"}]))
        sys.exit(1)

    print(json.dumps(run_parser(sys.argv[1]), indent=2))