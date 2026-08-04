topic = 'Dynamic Data Masking & Code Sanitization'

import ast

class PrivateSanitizer(ast.NodeTransformer):
    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        if node.attr.startswith('secret_') or node.attr == 'password':
            print(f'Sanitizing sensitive attribute node: {node.attr}')
            return ast.Constant(value='[REDACTED_SENSITIVE_DATA]')
        return self.generic_visit(node)

source_script = '''
user_input = user.password\nprint(user.secret_key)
password = 1 + 3 * 4
'''
#2nd line triggers callback warning | 3rd line works

tree = ast.parse(source_script)
sanitized_tree = PrivateSanitizer().visit(tree)
ast.fix_missing_locations(sanitized_tree)

print(ast.unparse(sanitized_tree))