import datetime
import json
import collections


DEFAULT_ENCODING = 'utf-8'


def map_nested_dicts(ob, func):
    if isinstance(ob, collections.Mapping):
        return {k: map_nested_dicts(v, func) for k, v in ob.iteritems()}
    else:
        return func(ob)


def json_encoder(o):
    if type(o) is datetime.date or type(o) is datetime.datetime:
        return o.isoformat()

    if isinstance(o, unicode):
        return o.encode('utf-8', errors='ignore')

    if isinstance(o, str):
        return o.encode('utf-8', errors='ignore')


def smart_str(s, encoding=DEFAULT_ENCODING, errors='ignore'):
    """
    Return a byte-string version of 's', encoded as specified in 'encoding'.
    """
    if isinstance(s, unicode):
        return s.encode(encoding, errors)

    # Already a byte-string, nothing to do here
    if isinstance(s, str):
        return s

    return s


def json_write(filename, data):
    data = map_nested_dicts(data, smart_str)

    data_str = json.dumps(data,
                          indent=4,
                          sort_keys=True,
                          default=json_encoder)

    file(filename, 'wb').write(data_str)
