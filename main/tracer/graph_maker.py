import re

from graphviz import Digraph

def make_graph(res_tree, main_pid, res_path):
	dot = Digraph()

	# Build nodes
	for pid, par in res_tree.items():
		dot.node(pid, f"{pid}\n{get_exe(par.get("Image"))}")

	# Build edges
	for pid, par in res_tree.items():
		children = par.get("Children")
		for c in children:
			dot.edge(pid, c)

	dot.render(f"{res_path}/trace_results/{main_pid}_process_tree", format="png", view=False)


def get_exe(image):
    if isinstance(image, list):
        image = image[-1] if image else ""  # usa o último valor visto
    pattern = r"\\[^\\]+\..*"
    if re.search(pattern, image):
        return re.search(pattern, image).group(0)[1:]
    return 1