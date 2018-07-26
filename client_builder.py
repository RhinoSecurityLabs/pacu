from types import MethodType

class Client_Builder:

    def dangerous_func(func):
        BAD_ACTIONS = ['describe_instances']
        if func.__name__ in BAD_ACTIONS:
            return True
        else:
            return False
        
    def allow(func):
        def allow_and_call(*args, **kwargs):
            if Client_Builder.dangerous_func(func):
                raise Exception("Can't do this function in recon mode")
            return func(*args, **kwargs)
        return allow_and_call

    def __init__(self, client):
        funcs = [func for func in dir(client) if isinstance(getattr(client, func), MethodType)]
        for func in funcs:
            setattr(self, func, Client_Builder.allow(getattr(client, func)))
