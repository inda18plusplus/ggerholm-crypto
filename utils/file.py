import json

from nacl.encoding import HexEncoder
from nacl.hash import sha256


def read_certificate(filename):
    content = ''
    with open('certificates/' + filename, 'r') as f:
        for line in f.readlines():
            content += line
    return content


def generate_certificate(filename, content):
    hashed_content = sha256(bytes(content, encoding='utf-8'), encoder=HexEncoder).decode('utf-8')
    with open('certificates/' + filename, 'w') as f:
        f.write(hashed_content)
    return hashed_content


def _json_object_hook(data):
    return File(data['file_id'], data['data'])


def file_from_json(data):
    return json.loads(data, object_hook=_json_object_hook)


def file_to_json(file):
    return json.dumps(file, default=lambda o: o.__dict__)


class File(object):
    def __init__(self, file_id, file_data):
        self.file_id = file_id
        self.data = file_data