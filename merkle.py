from nacl.encoding import HexEncoder
from nacl.hash import sha256

HASHER = sha256


# TODO: Test

class MerkleTree(object):
    top_node = None

    def __init__(self, foundation_length=16, foundation=None):
        self.foundation = []
        if foundation:
            for n in foundation:
                if not n:
                    self.foundation.append(None)
                else:
                    self.foundation.append(TreeNode(None, None, bytes(n, encoding='utf-8')))
            self.build()
        else:
            for i in range(0, foundation_length):
                self.foundation.append(None)

    def add_file(self, file):
        node = TreeNode(None, None, HASHER(bytes(file.data, encoding='utf-8'), encoder=HexEncoder))
        self.foundation[file.file_id] = node
        self.build()

    def build(self):
        nodes = list(filter(None, self.foundation.copy()))
        next_level = []

        while len(nodes) > 1:
            for i in range(0, len(nodes), 2):
                if i == len(nodes) - 1:
                    next_level.append(nodes[i])
                    break

                left = nodes[i]
                right = nodes[i + 1]
                node = TreeNode(left, right)
                next_level.append(node)
            nodes = next_level.copy()
            next_level = []

        self.top_node = nodes[0] if len(nodes) > 0 else None


class TreeNode(object):
    left_child = None
    right_child = None
    node_hash = None

    def __init__(self, left_child, right_child, node_hash=None):
        self.left_child = left_child
        self.right_child = right_child
        if left_child and right_child:
            self.node_hash = HASHER(left_child.node_hash + right_child.node_hash, encoder=HexEncoder)
        else:
            self.node_hash = node_hash

    def __str__(self):
        return str(self.node_hash)
