import abc
import itertools

import io
import os

from typing import List, Iterator

import botocore

from modules.iam__pivot.common import Escalation

from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.common import Node, Policy
from principalmapper.querying.local_policy_simulation import policy_has_matching_statement, \
    policies_include_matching_allow_action

policy_allow_all = Policy("arn:aws:iam::922105094392:policy/policy_allow_all", "policy_allow_all", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::*:role/*"
            },
            "Action": "sts:AssumeRole"
        }
    ]
})


class EscalationChecker(EdgeChecker):
    identity = None

    def __init__(self, session: botocore.session.Session):
        self.session = session
        self.required_dest_trust_policy_actions: List = []
        self.required_source_actions: List = []

        # If True stop looking for path's once we find an admin role
        self.filter_source_admin: bool = True

    @classmethod
    def _setup(cls, self):
        """Since __init__ will be called for every subclass, cache anything expensive as class attributes here."""
        sts = self.session.create_client('sts')
        cls.identity = sts.get_caller_identity()

    def setup(self):
        """SubClasses can set various config options here without needing to override __init__() and call super()"""
        pass

    @abc.abstractmethod
    def escalations(self, source: Iterator[Node], dest: Iterator[Node]) -> Iterator[Escalation]:
        """By default we call can_escalate_to_role and can_escalate_to_user for each source/dest
        you can override this and/or ignore both can_escalate_to_role and can_escalate_to_user
        if you want.
        """

    def _filter_sources(self, source: Node) -> bool:
        """ Uses the Config dataclass to filter nodes from being sent to subclasses, filtering is done in the base class
        to avoid O(N^2) processing on the size of the node list.
        """
        if self.filter_source_admin and source.is_admin:
            return False

        for action in self.required_source_actions:
            if not policies_include_matching_allow_action(source, action):
                return False

        return True

    def _filter_dests(self, dest: Node) -> bool:
        for action in self.required_dest_trust_policy_actions:
            if not policy_has_matching_statement(policy_allow_all, 'Allow', action, dest, {}) \
                    or policy_has_matching_statement(policy_allow_all, 'Deny', action, dest, {}):
                return False

        if ':user/' in dest.arn or dest.arn == self.identity["Arn"]:
            return False

        return True

    def _subclass_escalations(self, srcs: Iterator[Node], dsts: Iterator[Node]) -> Iterator[Escalation]:
        self._setup(self)
        for sub_cls in self.__class__.__subclasses__():
            inst = sub_cls(self.session)
            inst.setup()

            # Use sub_cls's filters before we run product to avoid O(N^2) processing on the size of the node list.
            srcs = filter(inst._filter_sources, srcs)
            dsts = filter(inst._filter_dests, dsts)

            for source, dest in itertools.product(srcs, dsts):
                yield from inst.escalations(source, dest)

    def return_edges(self, nodes: List[Node], output: io.StringIO = io.StringIO(os.devnull), debug: bool = False) -> \
            List[Escalation]:
        return list(self._subclass_escalations(iter(nodes.copy()), iter(nodes.copy())))