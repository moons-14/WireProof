from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network

from pydantic import BaseModel, ConfigDict, Field, model_validator

RT_RE = re.compile(r"^(?:target:)?(?:\d+|\d+\.\d+\.\d+\.\d+):\d+$")
RD_RE = re.compile(r"^(?:\d+|\d+\.\d+\.\d+\.\d+):\d+$")


class AddressFamily(StrEnum):
    IPV4_UNICAST = "ipv4-unicast"
    IPV6_UNICAST = "ipv6-unicast"
    L2VPN_EVPN = "l2vpn-evpn"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Clause(StrictModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]+$")
    statement: str


class Interface(StrictModel):
    name: str = Field(min_length=1)
    addresses: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_addresses(self) -> Interface:
        for address in self.addresses:
            try:
                if "." in address:
                    IPv4Network(address, strict=False)
                else:
                    IPv6Network(address, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid interface address {address}") from exc
        return self


class Node(StrictModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
    roles: frozenset[str] = frozenset()
    interfaces: tuple[Interface, ...] = ()

    @model_validator(mode="after")
    def unique_interfaces(self) -> Node:
        if len({interface.name for interface in self.interfaces}) != len(self.interfaces):
            raise ValueError(f"node {self.name} has duplicate interfaces")
        return self


class LinkEnd(StrictModel):
    node: str
    interface: str


class Link(StrictModel):
    a: LinkEnd
    b: LinkEnd

    @model_validator(mode="after")
    def distinct_endpoints(self) -> Link:
        if self.a == self.b:
            raise ValueError("link endpoints must differ")
        return self


class VLAN(StrictModel):
    id: int = Field(ge=1, le=4094)
    name: str


class VRF(StrictModel):
    name: str
    tenant: str
    management: bool = False


class PrefixSet(StrictModel):
    name: str
    prefixes: tuple[str, ...]

    @model_validator(mode="after")
    def valid_prefixes(self) -> PrefixSet:
        for prefix in self.prefixes:
            try:
                IPv4Network(prefix) if "." in prefix else IPv6Network(prefix)
            except ValueError as exc:
                raise ValueError(f"invalid prefix {prefix}") from exc
        return self


class CommunitySet(StrictModel):
    name: str
    communities: tuple[str, ...]


class RoutePolicyTerm(StrictModel):
    name: str
    prefix_set: str | None = None
    community_set: str | None = None
    action: str = Field(pattern=r"^(permit|deny)$")


class RoutePolicy(StrictModel):
    name: str
    terms: tuple[RoutePolicyTerm, ...]


class BGPSession(StrictModel):
    local_node: str
    remote_node: str
    local_as: int = Field(ge=1, le=4_294_967_295)
    remote_as: int = Field(ge=1, le=4_294_967_295)
    address_families: frozenset[AddressFamily]
    export_policy: str | None = None

    @model_validator(mode="after")
    def compatible_af(self) -> BGPSession:
        if not self.address_families:
            raise ValueError("BGP session requires at least one address family")
        return self


class VTEP(StrictModel):
    node: str
    source_interface: str
    peers: frozenset[str] = frozenset()


class EVPNInstance(StrictModel):
    name: str
    tenant: str
    rd: str
    import_rts: frozenset[str]
    export_rts: frozenset[str]
    shared_service: bool = False

    @model_validator(mode="after")
    def valid_rd_rts(self) -> EVPNInstance:
        if not RD_RE.fullmatch(self.rd):
            raise ValueError(f"invalid RD {self.rd}")
        for rt in self.import_rts | self.export_rts:
            if not RT_RE.fullmatch(rt):
                raise ValueError(f"invalid RT {rt}")
        if not self.import_rts or not self.export_rts:
            raise ValueError("EVPN instance requires import and export RT")
        if not self.import_rts & self.export_rts:
            raise ValueError("EVPN instance import/export RTs must intersect")
        return self


class L2VNI(StrictModel):
    vni: int = Field(ge=1, le=16_777_215)
    vlan: int
    evpn_instance: str
    vtep: str


class L3VNI(StrictModel):
    vni: int = Field(ge=1, le=16_777_215)
    vrf: str
    evpn_instance: str
    vtep: str
    symmetric_irb: bool = True


class StaticFDBEntry(StrictModel):
    mac: str = Field(pattern=r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
    vlan: int
    vtep: str


class FeatureContract(StrictModel):
    clauses: tuple[Clause, ...] = ()
    nodes: tuple[Node, ...]
    links: tuple[Link, ...]
    vlans: tuple[VLAN, ...]
    vrfs: tuple[VRF, ...]
    prefix_sets: tuple[PrefixSet, ...] = ()
    community_sets: tuple[CommunitySet, ...] = ()
    route_policies: tuple[RoutePolicy, ...] = ()
    management_export_policy: str | None = None
    bgp_sessions: tuple[BGPSession, ...]
    vteps: tuple[VTEP, ...]
    evpn_instances: tuple[EVPNInstance, ...]
    l2_vnis: tuple[L2VNI, ...]
    l3_vnis: tuple[L3VNI, ...]
    static_fdb: tuple[StaticFDBEntry, ...] = ()

    @model_validator(mode="after")
    def validate_references(self) -> FeatureContract:
        def unique(values: tuple[object, ...], attr: str, label: str) -> set[str | int]:
            keys = [getattr(value, attr) for value in values]
            if len(set(keys)) != len(keys):
                raise ValueError(f"duplicate {label}")
            return set(keys)

        node_names = unique(self.nodes, "name", "node")
        vlan_ids = unique(self.vlans, "id", "VLAN")
        vrf_names = unique(self.vrfs, "name", "VRF")
        vtep_nodes = unique(self.vteps, "node", "VTEP node")
        evi_names = unique(self.evpn_instances, "name", "EVPN instance")
        rds = [evi.rd for evi in self.evpn_instances]
        if len(set(rds)) != len(rds):
            raise ValueError("duplicate RD")
        vnis = [entry.vni for entry in self.l2_vnis] + [entry.vni for entry in self.l3_vnis]
        if len(set(vnis)) != len(vnis):
            raise ValueError("duplicate VNI")
        interfaces = {node.name: {i.name for i in node.interfaces} for node in self.nodes}
        for link in self.links:
            for end in (link.a, link.b):
                if end.node not in node_names or end.interface not in interfaces[end.node]:
                    raise ValueError(
                        f"link references missing interface {end.node}:{end.interface}"
                    )
        for session in self.bgp_sessions:
            if session.local_node not in node_names or session.remote_node not in node_names:
                raise ValueError("BGP session references missing node")
        bgp_peer_families = [
            (
                session.local_node,
                session.local_as,
                session.remote_node,
                session.remote_as,
                address_family,
            )
            for session in self.bgp_sessions
            for address_family in session.address_families
        ]
        if len(set(bgp_peer_families)) != len(bgp_peer_families):
            raise ValueError("duplicate BGP session peer address family")
        for vtep in self.vteps:
            if vtep.node not in node_names or vtep.source_interface not in interfaces[vtep.node]:
                raise ValueError(
                    f"VTEP references missing interface {vtep.node}:{vtep.source_interface}"
                )
            for peer in vtep.peers:
                if peer not in vtep_nodes:
                    raise ValueError(f"VTEP {vtep.node} references missing peer {peer}")
                peer_vtep = next(candidate for candidate in self.vteps if candidate.node == peer)
                if vtep.node not in peer_vtep.peers:
                    raise ValueError(f"asymmetric VTEP peer relationship {vtep.node}/{peer}")
        for l2_entry in self.l2_vnis:
            if l2_entry.evpn_instance not in evi_names or l2_entry.vtep not in vtep_nodes:
                raise ValueError("VNI references missing EVPN instance or VTEP")
        for l3_entry in self.l3_vnis:
            if l3_entry.evpn_instance not in evi_names or l3_entry.vtep not in vtep_nodes:
                raise ValueError("VNI references missing EVPN instance or VTEP")
        for l2 in self.l2_vnis:
            if l2.vlan not in vlan_ids:
                raise ValueError(f"L2VNI {l2.vni} references missing VLAN")
        for l3 in self.l3_vnis:
            if l3.vrf not in vrf_names or not l3.symmetric_irb:
                raise ValueError("L3VNI requires an existing VRF and symmetric IRB")
            evi = next(item for item in self.evpn_instances if item.name == l3.evpn_instance)
            vrf = next(item for item in self.vrfs if item.name == l3.vrf)
            if evi.tenant != vrf.tenant:
                raise ValueError("L3VNI EVPN instance tenant must match VRF tenant")
        for index, evi in enumerate(self.evpn_instances):
            evi_rts = evi.import_rts | evi.export_rts
            for other in self.evpn_instances[index + 1 :]:
                if (
                    evi.tenant != other.tenant
                    and evi_rts & (other.import_rts | other.export_rts)
                    and not (evi.shared_service or other.shared_service)
                ):
                    raise ValueError(
                        "cross-tenant RT sharing requires a shared-service EVPN instance"
                    )
        for fdb in self.static_fdb:
            if fdb.vlan not in vlan_ids or fdb.vtep not in vtep_nodes:
                raise ValueError("stale FDB entry references missing VLAN or VTEP")
        prefix_sets = {item.name for item in self.prefix_sets}
        community_sets = {item.name for item in self.community_sets}
        policy_names = {item.name for item in self.route_policies}
        for policy in self.route_policies:
            for term in policy.terms:
                if term.prefix_set and term.prefix_set not in prefix_sets:
                    raise ValueError("route policy references missing prefix set")
                if term.community_set and term.community_set not in community_sets:
                    raise ValueError("route policy references missing community set")
        for session in self.bgp_sessions:
            if session.export_policy and session.export_policy not in policy_names:
                raise ValueError("BGP session references missing export policy")
        if self.management_export_policy:
            if self.management_export_policy not in policy_names:
                raise ValueError("management export policy references missing policy")
            policy = next(p for p in self.route_policies if p.name == self.management_export_policy)
            # An unconstrained permit can export 0/0 and leak management reachability.
            prefix_set_by_name = {item.name: item for item in self.prefix_sets}
            if any(
                term.action == "permit"
                and (
                    term.prefix_set is None
                    or "0.0.0.0/0" in prefix_set_by_name[term.prefix_set].prefixes
                    or "::/0" in prefix_set_by_name[term.prefix_set].prefixes
                )
                for term in policy.terms
            ):
                raise ValueError("management export policy permits default route")
        evpn_participants = {vtep.node for vtep in self.vteps}
        for participant in evpn_participants:
            if not any(
                participant in (session.local_node, session.remote_node)
                and AddressFamily.L2VPN_EVPN in session.address_families
                for session in self.bgp_sessions
            ):
                raise ValueError(
                    f"EVPN participant {participant} requires a BGP session with l2vpn-evpn"
                )
        return self

    def canonical_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()
