import json


class File(object):
    def __init__(self):
        self.file_id = 1
        self.data = 'File data!'

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
