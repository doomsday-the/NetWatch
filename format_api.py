import ast

with open('backend/api.py', 'r', encoding='utf-8') as f:
    code = f.read()

# Check that it's valid AST
tree = ast.parse(code)
unparsed = ast.unparse(tree)

with open('backend/api.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(unparsed + '\n')

print(f"ast.unparse successfully formatted api.py into standard clean python!")
