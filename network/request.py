import json


def _json_object_hook(data):
    return Request(data['type'], data['data'])


def request_from_json(data):
    return json.loads(data, object_hook=_json_object_hook)


def request_to_json(request):
    return json.dumps(request, default=lambda o: o.__dict__)


class Request(object):
    def __init__(self, request_type, data):
        self.type = request_type.lower()
        self.data = data
