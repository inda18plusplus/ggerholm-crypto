import json

from utils.crypto import hash_sha256


def read_certificate(filename):
    try:
        content = ''
        with open('certificates/' + filename, 'r') as f:
            for line in f.readlines():
                content += line
        return content
    except FileNotFoundError:
        return None


def write_certificate(filename, certificate):
    with open('certificates/' + filename, 'w') as f:
        f.write(certificate)
    return certificate


def generate_certificate(filename, content):
    hashed_content = hash_sha256(bytes(content, encoding='utf-8')).decode('utf-8')
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
