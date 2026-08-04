topic = 'AST Sanitizer and Execution Program'

import ast
from typing import Any, Dict

class SecuritySafetyError(Exception):
    #more or less a label for smth went wrong based our on method for consuming it
    pass

class CodeExecutionSanitizer(ast.NodeVisitor):
    def __init__(self, forbidden_modules: set[str], forbidden_calls: set[str]):
        super().__init__()
        self.forbidden_modules = forbidden_modules
        self.forbidden_calls = forbidden_calls

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name in self.forbidden_modules:
                raise SecuritySafetyError(f'Forbidden module import \'{alias.name}\' detected at line {node.lineno}.')

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in self.forbidden_modules:
            raise SecuritySafetyError(f'Forbidden module import \'{node.name}\' detected at line {node.lineno}.')
        
        self.generic_visit(node) 

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name):
            if node.func.id in self.forbidden_calls:
                raise SecuritySafetyError(f'Forbidden execution call \'{node.func.id}\' detected at line {node.lineno}.')

        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                full_call = f'{node.func.value.id}.{node.func.attr}'
                if node.func.value.id in self.forbidden_modules or node.func.attr in self.forbidden_calls:
                    raise SecuritySafetyError(f'Forbidden execution call \'{full_call}\' detected at line {node.lineno}.')

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        if isinstance(node.attr, ast.Name):
            if node.attr == 'environ' or node.value.id in self.forbidden_modules: 
                raise SecuritySafetyError(f'Forbidden property access \'{node.value.id}.{node.attr}\' detected at line {node.lineno}.')

        self.generic_visit(node)
                           
def safely_execute_code(source_code: str) -> Dict[str, Any]:
    blocked_modules = {"os", "sys", "subprocess", "requests", "builtins"} #will prob add more
    blocked_calls = {"eval", "exec", "open", "getattr", "setattr", "compile"} #will prob add more

    try:
        tree = ast.parse(source_code)
    except SyntaxError as syntax_err:
        raise SecuritySafetyError(f'Syntax validation failed:  {syntax_err.msg} at line {syntax_err.lineno}')

    sanitizer = CodeExecutionSanitizer(blocked_modules, blocked_calls)
    sanitizer.visit(tree)

    compiled_bytecode = compile(tree, filename='<sandbox>', mode='exec')

    sandbox_globals: Dict[str, Any] = {'__builtins__': {}}
    sandbox_locals: Dict[str, Any] = {}

    exec(compiled_bytecode, sandbox_globals, sandbox_locals)

    #returns local variables mutated or created by the executed script
    return sandbox_locals


if __name__ == "__main__":
    # Test Case 1: Valid and Safe Script
    safe_script = """
def calculate_area(radius):
    return 3.14 * (radius ** 2)

result = calculate_area(5)
"""
    print("--- Running Safe Script ---")
    local_env = safely_execute_code(safe_script)
    print(f"Success! Script executed output variables: {local_env}")

    # Test Case 2: Malicious environment leak attempt
    malicious_script = """
import os
secret_env = os.environ.get('SECRET_KEY')
"""
    print("\n--- Running Malicious Script ---")
    try:
        safely_execute_code(malicious_script)
    except SecuritySafetyError as error:
        print(f"Blocked safely: {error}")

    # Test Case 3: Invalid Syntax Code
    broken_script = """
def test_func()
    print("Missing colon")
"""
    print("\n--- Running Broken Syntax Script ---")
    try:
        safely_execute_code(broken_script)
    except SecuritySafetyError as error:
        print(f"Blocked safely: {error}")