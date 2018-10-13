from file import File
from merkle import MerkleTree

tree = MerkleTree(16)

f2= File(0, 'Det här är fil nr 1!')
f4 = File(1, 'Det här är fil nr 2!')
f3 = File(2, 'Det här är fil nr 3!')
f1 = File(3, 'Det här är fil nr 4!')

tree.add_file(f1)
print(tree.top_node)
tree.add_file(f2)
print(tree.top_node)
tree.add_file(f3)
print(tree.top_node)
tree.add_file(f4)
print(tree.top_node)

