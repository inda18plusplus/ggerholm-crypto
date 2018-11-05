import json


def read_secret(filename: str):
    try:
        with open('secrets/' + filename, 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return None


def read_encryption_key(name_prefix: str, key: str):
    return bytes(read_secret('encryption/' + name_prefix + '_' + key + '.key'), encoding='utf-8')


def read_verification_key(name_prefix: str, key: str):
    return bytes(read_secret('verification/' + name_prefix + '_' + key + '.key'), encoding='utf-8')


def _json_object_hook(data):
    try:
        file_id = int(data['file_id'])
        data = str(data['data'])
        return File(file_id, data)
    except ValueError:
        raise


def file_from_json(data: str):
    return json.loads(data, object_hook=_json_object_hook)


def file_to_json(file: 'File'):
    return json.dumps(file, default=lambda o: o.__dict__)


class File(object):
    def __init__(self, file_id, file_data):
        self.file_id = file_id
        self.data = file_data
