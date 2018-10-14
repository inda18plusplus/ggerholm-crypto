import json


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
