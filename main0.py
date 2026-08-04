topic = 'Custom Math & Expression Evaluators'
math_op = "10 + (2 * 5.5)"

import ast
from typing import Optional

def evaluate_math_expression(expr_string: str) -> float:
    try:
        tree = ast.parse(expr_string, mode='eval')
    except SyntaxError as e:
        raise SyntaxError(f'Forbidden syntax structure & malformed expression... {e}')

    allowed_nodes = ( #tuple of allowed ast Types (prevents smth like os.loadenv() private key info)
        ast.Expression, 
        ast.BinOp, 
        ast.UnaryOp, 
        ast.Constant, 
        ast.operator, 
        ast.unaryop
    )

    #very interesting how ast.walk(tree) returns a list of node objs
    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            raise TypeError(f'Forbidden syntax structure or type... {type(node).__name__}')

    bytecode = compile(tree, filename='<math>', mode='eval')

    return eval(bytecode, {'__bulletins__': {}}, {})

print(evaluate_math_expression(topic))