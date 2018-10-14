import copy
import json

from nacl.encoding import HexEncoder
from nacl.hash import sha256

HASHER = sha256


# TODO: Test
# TODO: Documentation

def node_from_json(node_json):
    d = json.loads(node_json)
    return TreeNode.from_dictionary(d)


def node_to_json(node):
    return json.dumps(node.flatten())


def verify_top_hash(structure_json, top_hash):
    root_node = node_from_json(structure_json)
    root_node.fix_hash()
    return root_node.node_hash == top_hash


class MerkleTree(object):
    top_node = None

    def __init__(self, foundation_length=16):
        self.foundation = []
        for i in range(0, foundation_length):
            self.foundation.append(TreeNode())

    def add_file(self, file):
        node = TreeNode(None, None, bytes(file.data, encoding='utf-8'))
        self.foundation[file.file_id] = node
        self.build()

    def get_structure_with_file(self, file_id):
        k, m = 2, 0
        length = len(self.foundation)
        real_node = self.top_node
        node = TreeNode()
        root_node = node
        while k <= length:
            node.node_hash = None
            node.left_child = copy.deepcopy(real_node.left_child)
            node.right_child = copy.deepcopy(real_node.right_child)

            if file_id >= m + length / k:
                node.left_child = TreeNode()
                node.left_child.node_hash = real_node.left_child.node_hash
                node = node.right_child
                real_node = real_node.right_child
                m += length / k
            else:
                node.right_child = TreeNode()
                node.right_child.node_hash = real_node.right_child.node_hash
                node = node.left_child
                real_node = real_node.left_child

            k *= 2

        return root_node

    def build(self):
        nodes = self.foundation.copy()
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

    def __init__(self, left_child: 'TreeNode' = None, right_child: 'TreeNode' = None, node_hash: bytes = None):
        super().__init__()
        self.left_child = left_child
        self.right_child = right_child
        if node_hash:
            self.node_hash = HASHER(node_hash)
        else:
            self.fix_hash()

    def fix_hash(self):
        if not self.is_empty():
            return

        combined_hash = b''
        if self.left_child:
            self.left_child.fix_hash()
            if not self.left_child.is_empty():
                combined_hash += self.left_child.node_hash
        if self.right_child:
            self.right_child.fix_hash()
            if not self.right_child.is_empty():
                combined_hash += self.right_child.node_hash

        if combined_hash != b'':
            self.node_hash = HASHER(combined_hash, encoder=HexEncoder)

    def is_empty(self):
        return self.node_hash is None

    def flatten(self):
        return {
            'node_hash': self.node_hash.decode('utf-8').replace("'", '"') if self.node_hash else None,
            'left_child': self.left_child.flatten() if self.left_child else None,
            'right_child': self.right_child.flatten() if self.right_child else None
        }

    def __str__(self):
        return str(self.node_hash)

    @classmethod
    def from_dictionary(cls, dictionary):
        obj = cls()
        obj.node_hash = bytes(dictionary['node_hash'], encoding='utf-8') if dictionary['node_hash'] else None

        if 'left_child' in dictionary and dictionary['left_child'] is not None:
            obj.left_child = cls.from_dictionary(dictionary['left_child'])

        if 'right_child' in dictionary and dictionary['right_child'] is not None:
            obj.right_child = cls.from_dictionary(dictionary['right_child'])

        return obj
