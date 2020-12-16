from typing import Callable

from principalmapper.common import Edge, Node


class Escalation(Edge):
    def __init__(self, source: Node, destination: Node, escalate_func: Callable, reason: str = None):
        self.reason = reason or "can access via {}".format(str(escalate_func))

        super().__init__(source=source, destination=destination, reason=self.reason)

        self.source = source
        self.destination = destination
        self.escalate_func = escalate_func

    def run(self, *args, **kwargs):
        kwargs["source"] = self.source
        kwargs["target"] = self.destination
        self.escalate_func(*args, **kwargs)
