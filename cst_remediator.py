import sys
import libcst as cst
import libcst.matchers as m

class SecurityTransformer(cst.CSTTransformer):
    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.CSTNode:
        
        # Rule: CWE-95 (eval -> ast.literal_eval)
        if m.matches(original_node.func, m.Name("eval")):
            return updated_node.with_changes(
                func=cst.parse_expression("ast.literal_eval")
            )
        
        # Rule: CWE-78 (os.system -> subprocess.run)
        if m.matches(original_node.func, m.Attribute(value=m.Name("os"), attr=m.Name("system"))):
            cmd_arg = updated_node.args[0]
            
            return cst.Call(
                func=cst.parse_expression("subprocess.run"),
                args=[
                    cst.Arg(value=cst.Call(
                        func=cst.parse_expression("shlex.split"),
                        args=[cmd_arg]
                    )),
                    cst.Arg(
                        keyword=cst.Name("check"),
                        equal=cst.AssignEqual(
                            whitespace_before=cst.SimpleWhitespace(""), 
                            whitespace_after=cst.SimpleWhitespace("")
                        ),
                        value=cst.Name("True")
                    )
                ]
            )
            
        return updated_node

class ImportFixer(cst.CSTTransformer):
    def leave_Module(self, original_node: cst.Module, updated_node: cst.Module) -> cst.Module:
        # Check existing imports in the module
        existing_code = original_node.code
        
        imports_to_add = []
        if "import ast" not in existing_code:
            imports_to_add.append("import ast")
        if "import subprocess" not in existing_code:
            imports_to_add.append("import subprocess")
        if "import shlex" not in existing_code:
            imports_to_add.append("import shlex")

        if not imports_to_add:
            return updated_node

        import_str = "\n".join(imports_to_add) + "\n"
        secure_imports = cst.parse_module(import_str).body
        new_body = tuple(secure_imports) + updated_node.body
        return updated_node.with_changes(body=new_body)

def apply_fixes(file_path):
    try:
        with open(file_path, "r") as f:
            source = f.read()

        tree = cst.parse_module(source)
        
        patched_tree = tree.visit(SecurityTransformer())
        final_tree = patched_tree.visit(ImportFixer())

        with open(file_path, "w") as f:
            f.write(final_tree.code)
            
        print(f"[*] Auto-remediation complete. Secure fixes applied directly to '{file_path}'.")
        
    except FileNotFoundError:
        print(f"Error: Target file '{file_path}' not found.")
    except Exception as e:
        print(f"Error processing file: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cst_remediator.py <target_file.py>")
        sys.exit(1)
        
    apply_fixes(sys.argv[1])