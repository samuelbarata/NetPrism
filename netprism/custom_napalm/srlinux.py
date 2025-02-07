from napalm_srl.srl import NokiaSRLDriver
# https://github.com/napalm-automation-community/napalm-srlinux/blob/main/napalm_srl/srl.py

from napalm.base.helpers import convert, as_number
import logging
import datetime


# import requests

class CustomSRLDriver(NokiaSRLDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        opt_args = {
            "target_name": hostname,
            "skip_verify": False,
            "insecure": False,
        }
        opt_args.update(optional_args)
        super().__init__(hostname, username, password, timeout, opt_args)

    def get_facts(self):
        """
            Returns a dictionary containing the following information:
                uptime - Uptime of the device in seconds.
                vendor - Manufacturer of the device.
                model - Device model.
                hostname - Hostname of the device
                fqdn - Fqdn of the device
                os_version - String with the OS version running on the device.
                serial_number - Serial number of the device
                interface_list - List of the interfaces of the device
        """

        # Providing path for getting information from router
        try:
            path = {"/platform/chassis", "system/information", "system/name/host-name"}
            interface_path = {"interface[name=*]"}
            pathType = "STATE"

            output = self.device._gnmiGet("", path, pathType)
            interface_output = self.device._gnmiGet("", interface_path, pathType)

            # defining output variables
            interface_list = []
            uptime = -1.0
            version = ""
            hostname = ""
            serial_number = ""
            chassis_type = ""
            # getting interface names from the list
            for interface in interface_output["srl_nokia-interfaces:interface"]:
                interface_list.append(interface["name"])
            # getting system and platform information
            for key, value in output.items():
                if "system" in key and isinstance(value, dict):
                    for key_1, value_1 in value.items():
                        if "information" in key_1:
                            version = self._find_txt(value_1, "version")
                            uptime = self._find_txt(value_1, "uptime")
                            if uptime:
                                uptime = datetime.datetime.strptime(
                                    uptime, "%Y-%m-%dT%H:%M:%S.%fZ"
                                ).timestamp()
                            else:
                                current_time = datetime.datetime.strptime(value_1["current-datetime"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
                                last_boot = datetime.datetime.strptime(value_1["last-booted"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
                                uptime = current_time - last_boot
                        if "name" in key_1:
                            hostname = self._find_txt(value_1, "host-name")
                if "platform" in key and isinstance(value, dict):
                    for key_1, value_1 in value.items():
                        if "chassis" in key_1:
                            chassis_type = self._find_txt(value_1, "type")
                            serial_number = self._find_txt(value_1, "serial-number")
            return {
                "hostname": hostname,
                "fqdn": hostname,
                "vendor": u"Nokia",
                "model": chassis_type,
                "serial_number": serial_number,
                "os_version": version,
                "uptime": convert(float, uptime, default=-1.0),
                "interface_list": interface_list,
            }
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    # BGP peers
    def get_bgp_neighbors(self):
        """
            Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf
            (global if no vrf). The inner dictionary will contain the following data for each vrf:

                router_id
                peers - another dictionary of dictionaries. Outer keys are the IPs of the neighbors.
                The inner keys are:
                    local_as (int)
                    remote_as (int)
                    remote_id - peer router id
                    is_up (True/False)
                    is_enabled (True/False)
                    description (string)
                    uptime (int in seconds)
                    address_family (dictionary) - A dictionary of address families available for
                    the neighbor.
                    So far it can be ‘ipv4’ or ‘ipv6’
                        received_prefixes (int)
                        accepted_prefixes (int)
                        sent_prefixes (int)
                Note, if is_up is False and uptime has a positive value then this indicates the
                uptime of the last active BGP session.
        """
        try:
            bgp_neighbors = {
                "global": {
                    "router_id": "",
                    "peers": {}
                }
            }
            system_date_time = ""

            def _build_prefix_dict():
                prefix_limit = {}
                ipv4_unicast = self._find_txt(bgp_neighbor, "ipv4-unicast")
                if ipv4_unicast:
                    ipv4_unicast = eval(ipv4_unicast.replace("'", '"'))
                    prefix_limit.update(
                        {
                            "ipv4": {
                                "sent_prefixes": convert(
                                    int,
                                    self._find_txt(ipv4_unicast, "sent-routes"),
                                    default=-1,
                                ),
                                "received_prefixes": convert(
                                    int,
                                    self._find_txt(ipv4_unicast, "received-routes"),
                                    default=-1,
                                ),
                                "accepted_prefixes": convert(
                                    int,
                                    self._find_txt(ipv4_unicast, "active-routes"),
                                    default=-1,
                                ),
                            }
                        }
                    )
                ipv6_unicast = self._find_txt(bgp_neighbor, "ipv6-unicast")
                if ipv6_unicast:
                    ipv6_unicast = eval(ipv6_unicast.replace("'", '"'))
                    prefix_limit.update(
                        {
                            "ipv6": {
                                "sent_prefixes": convert(
                                    int,
                                    self._find_txt(ipv6_unicast, "sent-routes"),
                                    default=-1,
                                ),
                                "received_prefixes": convert(
                                    int,
                                    self._find_txt(ipv6_unicast, "received-routes"),
                                    default=-1,
                                ),
                                "accepted_prefixes": convert(
                                    int,
                                    self._find_txt(ipv6_unicast, "active-routes"),
                                    default=-1,
                                ),
                            }
                        }
                    )
                return prefix_limit

            path = {"/network-instance[name=*]"}
            system_path = {"system/information"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)
            system_output = self.device._gnmiGet("", system_path, pathType)

            for key, value in system_output["srl_nokia-system:system"].items():
                system_date_time = self._find_txt(value, "current-datetime")
                if system_date_time:
                    system_date_time = datetime.datetime.strptime(
                        system_date_time, "%Y-%m-%dT%H:%M:%S.%fZ"
                    ).timestamp()

            for network_instance in output["srl_nokia-network-instance:network-instance"]:
                instance_name = self._find_txt(network_instance, "name")
                router_id = self._find_txt(network_instance, "router-id")
                global_autonomous_system_number = self._find_txt(
                    network_instance, "autonomous-system",
                )
                bgp_neighbors.update({instance_name: {"router_id": router_id, "peers": {}}})
                protocols = self._find_txt(network_instance, "protocols")
                if protocols:
                    protocols = eval(protocols.replace("'", '"'))
                    bgp_dict = self._find_txt(protocols, "srl_nokia-bgp:bgp")
                    if bgp_dict:
                        bgp_dict = eval(bgp_dict.replace("'", '"'))
                        bgp_neighbors_list = self._find_txt(bgp_dict, "neighbor")
                        if bgp_neighbors_list:
                            bgp_neighbors_list = list(
                                eval(bgp_neighbors_list.replace("'", '"'))
                            )
                            for bgp_neighbor in bgp_neighbors_list:
                                peer_ip = self._find_txt(bgp_neighbor, "peer-address")
                                if peer_ip:
                                    local_as = self._find_txt(bgp_neighbor, "local-as")
                                    explicit_peer_as = self._find_txt(
                                        bgp_neighbor, "peer-as"
                                    )

                                    local_as_number = -1
                                    peer_as_number = (
                                        explicit_peer_as
                                        if explicit_peer_as
                                        else global_autonomous_system_number
                                    )
                                    if local_as:
                                        local_as = [eval(local_as.replace("'", '"'))]

                                        for dictionary in local_as:
                                            explicit_local_as_number = self._find_txt(
                                                dictionary, "as-number"
                                            )
                                            local_as_number = (
                                                explicit_local_as_number
                                                if explicit_local_as_number
                                                else global_autonomous_system_number
                                            )
                                    last_established = self._find_txt(
                                        bgp_neighbor, "last-established"
                                    )
                                    if last_established:
                                        last_established = datetime.datetime.strptime(
                                            last_established, "%Y-%m-%dT%H:%M:%S.%fZ"
                                        ).timestamp()
                                    bgp_neighbors[instance_name]["peers"].update(
                                        {
                                            peer_ip: {
                                                "local_as": as_number(local_as_number),
                                                "remote_as": as_number(peer_as_number),
                                                "remote_id": peer_ip,
                                                "is_up": True
                                                if self._find_txt(
                                                    bgp_neighbor, "session-state"
                                                )
                                                   == "established"
                                                else False,
                                                "is_enabled": True
                                                if self._find_txt(
                                                    bgp_neighbor, "admin-state"
                                                )
                                                   == "enable"
                                                else False,
                                                "description": self._find_txt(
                                                    bgp_neighbor, "description"
                                                ),
                                                "uptime": convert(
                                                    int,
                                                    (system_date_time - last_established) if isinstance(last_established,
                                                                                                        float) else -1,
                                                    default=-1,
                                                ),
                                                "address_family": _build_prefix_dict(),
                                            }
                                        }
                                    )

            return bgp_neighbors
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """
            :param neighbor_address:
            :return:
                Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).
                The keys of the inner dictionary represent the AS number of the neighbors.
                Leaf dictionaries contain the following fields:
                    up (True/False)
                    local_as (int)
                    remote_as (int)
                    router_id (string)
                    local_address (string)
                    routing_table (string)
                    local_address_configured (True/False)
                    local_port (int)
                    remote_address (string)
                    remote_port (int)
                    multihop (True/False)
                    multipath (True/False)
                    remove_private_as (True/False)
                    import_policy (string)
                    export_policy (string)
                    input_messages (int)
                    output_messages (int)
                    input_updates (int)
                    output_updates (int)
                    messages_queued_out (int)
                    connection_state (string)
                    previous_connection_state (string)
                    last_event (string)
                    suppress_4byte_as (True/False)
                    local_as_prepend (True/False)
                    holdtime (int)
                    configured_holdtime (int)
                    keepalive (int)
                    configured_keepalive (int)
                    active_prefix_count (int)
                    received_prefix_count (int)
                    accepted_prefix_count (int)
                    suppressed_prefix_count (int)
                    advertised_prefix_count (int)
                    flap_count (int)

        """
        try:
            bgp_neighbor_detail = {}

            path = {"/network-instance[name=*]"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for network_instance in output["srl_nokia-network-instance:network-instance"]:
                instance_name = self._find_txt(network_instance, "name")
                router_id = self._find_txt(network_instance, "router-id")
                global_autonomous_system_number = self._find_txt(
                    network_instance, "autonomous-system",
                )
                protocols = self._find_txt(network_instance, "protocols")
                if protocols:
                    protocols = eval(protocols.replace("'", '"'))
                    bgp_dict = self._find_txt(protocols, "srl_nokia-bgp:bgp")
                    if bgp_dict:
                        bgp_dict = eval(bgp_dict.replace("'", '"'))
                        bgp_neighbors_list = self._find_txt(bgp_dict, "neighbor")
                        if bgp_neighbors_list:
                            bgp_neighbors_list = list(
                                eval(bgp_neighbors_list.replace("'", '"'))
                            )
                            bgp_neighbor_detail[instance_name] = {}
                            for bgp_neighbor in bgp_neighbors_list:
                                peer_ip = self._find_txt(bgp_neighbor, "peer-address")
                                if peer_ip:
                                    if neighbor_address and not neighbor_address == peer_ip:
                                        continue
                                    local_as = self._find_txt(bgp_neighbor, "local-as")
                                    explicit_peer_as = self._find_txt(
                                        bgp_neighbor, "peer-as"
                                    )
                                    local_as_number = -1
                                    peer_as_number = (
                                        explicit_peer_as
                                        if explicit_peer_as
                                        else global_autonomous_system_number
                                    )

                                    if local_as:
                                        local_as = [eval(local_as.replace("'", '"'))]
                                        for dictionary in local_as:
                                            explicit_local_as_number = self._find_txt(
                                                dictionary, "as-number"
                                            )
                                            local_as_number = (
                                                explicit_local_as_number
                                                if explicit_local_as_number
                                                else global_autonomous_system_number
                                            )
                                    transport = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "transport")
                                    )
                                    local_address = ""
                                    if transport:
                                        local_address = self._find_txt(
                                            transport, "local-address"
                                        )
                                    timers = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "timers")
                                    )
                                    sent_messages = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "sent-messages")
                                    )
                                    received_messages = self._str_to_dict(
                                        self._find_txt(
                                            bgp_neighbor, "received-messages"
                                        )
                                    )

                                    ipv4_unicast = list(filter(lambda x: x['afi-safi-name'] == 'srl_nokia-common:ipv4-unicast', bgp_neighbor['afi-safi']))[0]
                                    active_ipv4 = ipv4_unicast.get('active-routes', -1)
                                    received_ipv4 = ipv4_unicast.get('received-routes', -1)
                                    suppressed_ipv4 = ipv4_unicast.get('rejected-routes', -1)
                                    advertised_ipv4 = ipv4_unicast.get('sent-routes', -1)
                                    evpn = list(filter(lambda x: x['afi-safi-name'] == 'srl_nokia-common:evpn', bgp_neighbor['afi-safi']))[0]
                                    active_evpn = evpn.get('active-routes', -1)
                                    received_evpn = evpn.get('received-routes', -1)
                                    suppressed_evpn = evpn.get('rejected-routes', -1)
                                    advertised_evpn = evpn.get('sent-routes', -1)
                                    ipv6_unicast = list(filter(lambda x: x['afi-safi-name'] == 'srl_nokia-common:ipv6-unicast', bgp_neighbor['afi-safi']))[0]
                                    active_ipv6 = ipv6_unicast.get('active-routes', -1)
                                    received_ipv6 = ipv6_unicast.get('received-routes', -1)
                                    suppressed_ipv6 = ipv6_unicast.get('rejected-routes', -1)
                                    advertised_ipv6 = ipv6_unicast.get('sent-routes', -1)

                                    active_prefix_count = -1
                                    received_prefix_count = -1
                                    accepted_prefix_count = -1
                                    suppressed_prefix_count = -1
                                    advertised_prefix_count = -1

                                    if active_ipv4 != -1:
                                        active_prefix_count = active_ipv4
                                        received_prefix_count = received_ipv4
                                        accepted_prefix_count = active_ipv4
                                        suppressed_prefix_count = suppressed_ipv4
                                        advertised_prefix_count = advertised_ipv4
                                    elif active_evpn != -1:
                                        active_prefix_count = active_evpn
                                        received_prefix_count = received_evpn
                                        accepted_prefix_count = active_evpn
                                        suppressed_prefix_count = suppressed_evpn
                                        advertised_prefix_count = advertised_evpn
                                    elif active_ipv6 != -1:
                                        active_prefix_count = active_ipv6
                                        received_prefix_count = received_ipv6
                                        accepted_prefix_count = active_ipv6
                                        suppressed_prefix_count = suppressed_ipv6
                                        advertised_prefix_count = advertised_ipv6

                                    peer_data = {
                                        "up": True
                                        if self._find_txt(
                                            bgp_neighbor, "session-state"
                                        )
                                           == "established"
                                        else False,
                                        "local_as": as_number(local_as_number),
                                        "remote_as": as_number(peer_as_number),
                                        "router_id": router_id,
                                        "local_address": local_address,
                                        "routing_table": self._find_txt(
                                            bgp_neighbor, "peer-group"
                                        ),
                                        "local_address_configured": False
                                        if local_address
                                        else True,
                                        "local_port": convert(
                                            int,
                                            self._find_txt(transport, "local-port"),
                                            default=-1,
                                        )
                                        if transport
                                        else -1,
                                        "remote_address": peer_ip,
                                        "remote_port": convert(
                                            int,
                                            self._find_txt(
                                                transport, "remote-port"
                                            ),
                                            default=-1,
                                        ),
                                        "multihop": False,  # Not yet supported in SRLinux
                                        "multipath": False,  # Not yet supported in SRLinux
                                        "remove_private_as": False,  # Not yet supported in SRLinux
                                        "import_policy": self._find_txt(
                                            bgp_neighbor, "import-policy"
                                        ),
                                        "export_policy": self._find_txt(
                                            bgp_neighbor, "export-policy"
                                        ),
                                        "input_messages": convert(
                                            int,
                                            self._find_txt(
                                                received_messages, "total-messages"
                                            ),
                                            default=-1,
                                        ),
                                        "output_messages": convert(
                                            int,
                                            self._find_txt(
                                                sent_messages, "total-messages"
                                            ),
                                            default=-1,
                                        ),
                                        "input_updates": convert(
                                            int,
                                            self._find_txt(
                                                received_messages, "total-updates"
                                            ),
                                            default=-1,
                                        ),
                                        "output_updates": convert(
                                            int,
                                            self._find_txt(
                                                sent_messages, "total-updates"
                                            ),
                                            default=-1,
                                        ),
                                        "messages_queued_out": convert(
                                            int,
                                            self._find_txt(
                                                sent_messages, "queue-depth"
                                            ),
                                            default=-1,
                                        ),
                                        "connection_state": self._find_txt(
                                            bgp_neighbor, "session-state"
                                        ),
                                        "previous_connection_state": self._find_txt(
                                            bgp_neighbor, "last-state"
                                        ),
                                        "last_event": self._find_txt(
                                            bgp_neighbor, "last-event"
                                        ),
                                        "suppress_4byte_as": False,  # Not yet supported in SRLinux
                                        "local_as_prepend": convert(
                                            bool,
                                            self._find_txt(
                                                local_as, "prepend-local-as"
                                            ),
                                            default=False,
                                        ),
                                        "holdtime": convert(
                                            int,
                                            self._find_txt(timers, "hold-time"),
                                            default=-1,
                                        ),
                                        "configured_holdtime": convert(
                                            int,
                                            self._find_txt(
                                                timers, "negotiated-hold-time"
                                            ),
                                            default=-1,
                                        ),
                                        "keepalive": convert(
                                            int,
                                            self._find_txt(
                                                timers, "keepalive-interval"
                                            ),
                                            default=-1,
                                        ),
                                        "configured_keepalive": convert(
                                            int,
                                            self._find_txt(
                                                timers,
                                                "negotiated-keepalive-interval",
                                            ),
                                            default=-1,
                                        ),
                                        "active_prefix_count": active_prefix_count,
                                        "received_prefix_count": received_prefix_count,
                                        "accepted_prefix_count": accepted_prefix_count,
                                        "suppressed_prefix_count": suppressed_prefix_count,
                                        "advertised_prefix_count": advertised_prefix_count,
                                        "flap_count": -1,  # Not yet supported in SRLinux
                                    }
                                    # )
                                    peer_as_number = as_number(peer_as_number)
                                    if peer_as_number in bgp_neighbor_detail[instance_name]:
                                        bgp_neighbor_detail[instance_name][peer_as_number].append(peer_data)
                                    else:
                                        bgp_neighbor_detail[instance_name][peer_as_number] = [peer_data]
            return bgp_neighbor_detail
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_arp_table(self, vrf=""):
        """
            Returns a list of dictionaries having the following set of keys:
                interface (string)
                mac (string)
                ip (string)
                age (float)
            ‘vrf’ of null-string will default to all VRFs.
            Specific ‘vrf’ will return the ARP table entries for that VRFs
             (including potentially ‘default’ or ‘global’).

            In all cases the same data structure is returned and no reference to the VRF that was
            used is included in the output.
        """
        try:
            arp_table = []
            subinterface_names = []

            def _find_neighbors(is_ipv4, ip_dict):
                ip_dict = eval(ip_dict.replace("'", '"'))
                neighbor_list = self._find_txt(ip_dict, "neighbor")
                if neighbor_list:
                    neighbor_list = list(eval(neighbor_list))
                    for neighbor in neighbor_list:
                        ipv4_address = ""
                        ipv6_address = ""
                        timeout = -1.0
                        reachable_time = -1.0
                        if is_ipv4:
                            ipv4_address = self._find_txt(neighbor, "ipv4-address")
                            timeout = convert(
                                float, self._find_txt(ip_dict, "timeout"), default=-1.0
                            )
                            if timeout == 14400.0 or timeout == -1.0:
                                try:
                                    ts = datetime.datetime.strptime(
                                        neighbor["expiration-time"], "%Y-%m-%dT%H:%M:%S.%fZ"
                                    )
                                    timeout = float((ts - datetime.datetime.now()).seconds)
                                except Exception as e:
                                    logging.error("Error occurred : {}".format(e))
                        else:
                            ipv6_address = self._find_txt(neighbor, "ipv6-address")
                            reachable_time = convert(
                                float,
                                self._find_txt(ip_dict, "reachable-time"),
                                default=-1.0,
                            )
                        arp_table.append(
                            {
                                "interface": sub_interface_name,
                                "mac": self._find_txt(neighbor, "link-layer-address"),
                                "ip": ipv4_address if is_ipv4 else ipv6_address,
                                "age": timeout if is_ipv4 else reachable_time,
                            }
                        )

            if vrf:
                vrf_path = {"network-instance[name={}]".format(vrf)}
            else:
                vrf_path = {"network-instance[name=*]"}
            pathType = "STATE"
            vrf_output = self.device._gnmiGet("", vrf_path, pathType)
            if not vrf_output:
                return []
            for vrf in vrf_output["srl_nokia-network-instance:network-instance"]:
                if "interface" in vrf.keys():
                    subinterface_list = self._find_txt(vrf, "interface")
                    subinterface_list = list(eval(subinterface_list))
                    for dictionary in subinterface_list:
                        if "name" in dictionary.keys():
                            subinterface_names.append(self._find_txt(dictionary, "name"))

            interface_path = {"interface[name=*]"}
            interface_output = self.device._gnmiGet("", interface_path, pathType)

            for interface in interface_output["srl_nokia-interfaces:interface"]:
                interface_name = self._find_txt(interface, "name")
                if interface_name:
                    sub_interface = self._find_txt(interface, "subinterface")
                    if sub_interface:
                        sub_interface = list(eval(sub_interface))
                        for dictionary in sub_interface:
                            sub_interface_name = self._find_txt(dictionary, "name")
                            if sub_interface_name in subinterface_names:
                                ipv4_data = self._find_txt(dictionary, "ipv4")
                                if ipv4_data:
                                    ipv4_data = eval(ipv4_data.replace("'", '"'))
                                    ipv4_arp_dict = self._find_txt(
                                        ipv4_data, "srl_nokia-interfaces-nbr:arp"
                                    )
                                    if ipv4_arp_dict:
                                        _find_neighbors(True, ipv4_arp_dict)

                                ipv6_data = self._find_txt(dictionary, "ipv6")
                                if ipv6_data:
                                    ipv6_data = eval(ipv6_data.replace("'", '"'))
                                    ipv6_neighbor_dict = self._find_txt(
                                        ipv6_data, "srl_nokia-if-ip-nbr:neighbor-discovery"
                                    )
                                    if ipv6_neighbor_dict:
                                        _find_neighbors(False, ipv6_neighbor_dict)
            return arp_table
        except Exception as e:
            logging.error("Error occurred : {}".format(e))
