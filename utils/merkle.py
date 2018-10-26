import copy
import json

from utils.crypto import hash_sha256
from utils.file import File


def node_from_json(node_json):
    d = json.loads(node_json)
    return TreeNode.from_dictionary(d)


def node_to_json(node):
    return json.dumps(node.flatten())


def get_root_hash(structure_json, file):
    """
    Calculates the root hash of the provided structure with the provided
    file included.
    :param structure_json: The structure of a minimal tree in JSON.
    :param file: The file whose hash is to be used.
    :return: The root hash of the merkle tree.
    """
    structure = node_from_json(structure_json)

    tree = MerkleTree()
    tree.root_node = structure
    validation_node = tree.get_structure_with_file(file, False)
    validation_node.fix_hash()
    return validation_node.node_hash


class MerkleTree(object):
    root_node = None

    def __init__(self, foundation_length=16):
        self.foundation = []
        for i in range(0, foundation_length):
            self.foundation.append(TreeNode())

    def insert_file(self, file: 'File'):
        """
        Inserts a file hash to the tree's foundation.
        The file_id decides the position of the leaf node.
        :param file: A File-object with a valid ID.
        """
        node = TreeNode(None, None, bytes(file.data, encoding='utf-8'))
        self.foundation[file.file_id] = node
        self.update(file)

    def get_structure_with_file(self, file, clear_file_hash=False):
        """
        Creates a tree structure with only the nodes that are required for the provided file to be
        verifiable.
        :param file: The file whose hash has to be included in the tree.
        :param clear_file_hash: If the file hash should be cleared out.
        :return: The root node of the newly created tree.
        """
        left_margin = 0
        width = len(self.foundation)
        real_node = self.root_node
        node = TreeNode()
        root_node = node
        while width > 1:
            node.node_hash = None
            node.left_child = copy.deepcopy(real_node.left_child)
            node.right_child = copy.deepcopy(real_node.right_child)

            # Because the tree is binary and the file ID corresponds to its leaf node's position
            # it can be decided whether the leaf node is to the left or right by comparing
            # the file ID with the remaining tree width.
            if file.file_id >= left_margin + width / 2:
                node.left_child = TreeNode()
                node.left_child.node_hash = real_node.left_child.node_hash
                node = node.right_child
                real_node = real_node.right_child
                # If the leaf node is to the right then half of the tree downwards is to the left,
                # which has to be accounted for during the above comparison.
                left_margin += width / 2
            else:
                node.right_child = TreeNode()
                node.right_child.node_hash = real_node.right_child.node_hash
                node = node.left_child
                real_node = real_node.left_child

            # Each step splits the tree in half
            width /= 2

        if clear_file_hash:
            node.node_hash = None
        else:
            node.node_hash = hash_sha256(bytes(file.data, encoding='utf-8'))

        return root_node

    def update(self, file: 'File'):
        """
        Traverses the tree and updates the hashes connected to the provided file, including the leaf node itself.
        :param file: A File-object with a valid ID.
        """
        left_margin = 0
        width = len(self.foundation)
        node = self.root_node
        nodes = [self.root_node]
        while width > 1:
            if file.file_id >= left_margin + width / 2:
                nodes.append(node.right_child)
                node = node.right_child
                left_margin += width / 2
            else:
                nodes.append(node.left_child)
                node = node.left_child
            width /= 2

        nodes[-1].node_hash = hash_sha256(bytes(file.data, encoding='utf-8'))
        for i in reversed(range(0, len(nodes) - 2)):
            nodes[i].node_hash = None
            nodes[i].fix_hash()

    def build(self):
        """
        Builds the tree from the bottom up.
        """
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

        self.root_node = nodes[0] if len(nodes) > 0 else None


class TreeNode(object):
    node_hash = None

    def __init__(self, left_child: 'TreeNode' = None, right_child: 'TreeNode' = None, node_data: bytes = None):
        super().__init__()
        self.left_child = left_child
        self.right_child = right_child
        if node_data:
            self.node_hash = hash_sha256(node_data)
        else:
            self.fix_hash()

    def fix_hash(self):
        """
        Calculates this node's hash based on its children's hashes.
        Does nothing if the node's hash is not empty.
        """
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
            self.node_hash = hash_sha256(combined_hash)

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

    def __eq__(self, other):
        if other and isinstance(other, TreeNode):
            if self.left_child != other.left_child:
                return False
            if self.right_child != other.right_child:
                return False
            return self.node_hash == other.node_hash
        return super().__eq__(other)

    @classmethod
    def from_dictionary(cls, dictionary):
        obj = cls()
        obj.node_hash = bytes(dictionary['node_hash'], encoding='utf-8') if dictionary['node_hash'] else None

        if 'left_child' in dictionary and dictionary['left_child'] is not None:
            obj.left_child = cls.from_dictionary(dictionary['left_child'])

        if 'right_child' in dictionary and dictionary['right_child'] is not None:
            obj.right_child = cls.from_dictionary(dictionary['right_child'])

        return obj
