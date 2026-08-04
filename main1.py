topic = 'Use Case 2: Linting & Static Code Analysis'

import ast

class SecurityLinter(ast.NodeVisitor):

    danger_set = {'os', 'subprocess', 'sys'} #set() for O(1) look-up time

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in self.danger_set:
                print(f'CRITICAL: Dangerous module import found at line {node.lineno}: {alias.name}')

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in self.danger_set:
            print(f'CRITICAL: Dangerous module from-import found at line {node.lineno}: {node.module}')

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == '__import__':
            if node.args and isinstance(node.args[0], ast.Constant):
                module_name = node.args[0].value
                if module_name in self.danger_set:
                    print(f"CRITICAL: Dynamic __import__ found at line {node.lineno}: {module_name}")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr == 'import_module' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'importlib':
                if node.args and isinstance(node.args[0], ast.Constant):
                    module_name = node.args[0].value
                    if module_name in self.danger_set:
                        print(f"CRITICAL: Dynamic importlib found at line {node.lineno}: {module_name}")

        self.generic_visit(node)


plugin_source = '''
import os
import math
import importlib

# Dynamic attempts
mod1 = __import__('subprocess')
mod2 = importlib.import_module('sys')

print("Hello World")

'''
#math & print statement work fine | os, sys are caught

linter = SecurityLinter()
linter.visit(ast.parse(plugin_source))