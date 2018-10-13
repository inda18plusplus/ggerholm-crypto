import nacl.encoding
import nacl.hash

HASHER = nacl.hash.sha256


class MerkleTree(object):
    top_node = None
    foundation = []

    def __init__(self, foundation_length=16, foundation=None):
        if foundation:
            self.foundation = foundation
            self.build()
        else:
            for i in range(0, foundation_length):
                self.foundation.append(None)

    def add_file(self, file):
        node = TreeNode(None, None, HASHER(bytes(file.data, encoding='utf-8'), encoder=nacl.encoding.HexEncoder))
        self.foundation[file.file_id] = node
        self.build()

    def build(self):
        nodes = list(filter(None, self.foundation.copy()))
        structure = []

        while len(nodes) > 1:
            for i in range(0, len(nodes), 2):
                if i == len(nodes) - 1:
                    structure.append(nodes[i])
                    break

                left = nodes[i]
                right = nodes[i + 1]
                node = TreeNode(left, right)
                structure.append(node)
            nodes = structure.copy()
            structure = []

        self.top_node = nodes[0] if len(nodes) > 0 else None


class TreeNode(object):
    left_child = None
    right_child = None
    node_hash = None

    def __init__(self, left_child, right_child, node_hash=None):
        self.left_child = left_child
        self.right_child = right_child
        if left_child and right_child:
            self.node_hash = HASHER(left_child.node_hash + right_child.node_hash, encoder=nacl.encoding.HexEncoder)
        else:
            self.node_hash = node_hash

    def __str__(self):
        return str(self.node_hash)
