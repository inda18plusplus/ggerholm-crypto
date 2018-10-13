import json


class File(object):
    def __init__(self, file_id, file_data):
        self.file_id = file_id
        self.data = file_data

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
