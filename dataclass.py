class Dataclass:
    dct: dict

    def __init__(self, **dct):
        object.__setattr__(self, "dct", dct)

    def __getattribute__(self, item):
        rval = object.__getattribute__(self, "dct")[item]
        if type(rval) == dict:
            return Dataclass(**rval)
        return rval

    def __setattr__(self, key, value):
        object.__getattribute__(self, "dct")[key] = value
