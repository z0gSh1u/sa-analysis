import pyan

cg = pyan.create_callgraph(r'F:/sa-analysis/yagmail-bad-smell/yagmail/**/*.py', format='dot', draw_defines=False, draw_uses=True)

with open('dot.dot', 'w') as f:
    f.write(cg)