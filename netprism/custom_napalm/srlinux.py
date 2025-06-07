import sys
import types
# Prevent gnmi_pb2 from being imported; would break pygnmi
sys.modules['napalm_srl.gnmi_pb2'] = types.ModuleType('napalm_srl.gnmi_pb2')

from napalm_srl.srl import NokiaSRLDriver, SRLAPI
# https://github.com/napalm-automation-community/napalm-srlinux/blob/main/napalm_srl/srl.py

from napalm.base.helpers import convert, as_number
from napalm.base.exceptions import ConnectionException
import logging
import datetime
import jmespath
from lark import Lark, Transformer, v_args
from pygnmi.client import gNMIclient, gNMIException
from pygnmi.client import logger as gnmi_logger
from grpc import StatusCode

TRACEROUTE_GRAMMAR = r"""
start: line*

line: hop
    | garbage

hop: HOP_NUM ping ping ping NEWLINE?

// PRIORITIES: Higher number = higher priority
RTT.3: /\d+(\.\d+)?\s*[a-z]+/
IP.2: "(" /[0-9.]+/ ")"
HOP_NUM.1: /\d+(?=\s)/
hostname: /[^\s()]+/

garbage: /[^\n]*\n/

ping: lost_ping | full_ping | simple_ping

lost_ping: "*"
full_ping: hostname IP RTT
simple_ping: RTT

%import common.NEWLINE
%import common.WS
%ignore WS
"""

@v_args(inline=True)
class TracerouteTransformer(Transformer):
    def __init__(self):
        super().__init__()
        self.result = {}
        self.last_ip = None
        self.last_hostname = None
        self.hop_index = 1

    def HOP_NUM(self, token):
        return int(token.value)
    def hostname(self, token):
        return token.value
    def IP(self, token):
        return token.value[1:-1] # Extract content from parentheses
    def RTT(self, token):
        return token.value # Returns the full string like "1.234 ms"
    def lost_ping(self):
        return {"type": "lost"}
    def NEWLINE(self, token):
        return {"type": "NEWLINE"}
    def simple_ping(self, rtt_string):
        return {"type": "simple", "rtt": rtt_string}
    def full_ping(self, hostname_string, ip_string, rtt_string):
        return {
            "type": "full",
            "hostname": hostname_string,
            "ip": ip_string,
            "rtt": rtt_string
        }
    def ping(self, ping_data_dictionary):
        return ping_data_dictionary

    def hop(self, hop_num_token, *pings):
        hop_num = int(hop_num_token)
        self.last_ip = None
        self.last_hostname = None
        probes = {}
        for i, ping in enumerate(pings, 1):
            if ping['type'] == 'NEWLINE':
                continue
            probe = {}
            if ping['type'] == 'lost':
                probe['rtt'] = '*'
                if self.last_ip is None:
                    self.last_ip = '*'
                    self.last_hostname = '*'
                probe['ip_address'] = self.last_ip
                probe['host_name'] = self.last_hostname
            else:
                probe['rtt'] = float(ping['rtt'].split()[0])
                if ping['type'] == 'simple':
                    probe['ip_address'] = self.last_ip
                    probe['host_name'] = self.last_hostname
                else:
                    self.last_ip = ping['ip']
                    self.last_hostname = ping['hostname']
                    probe['ip_address'] = self.last_ip
                    probe['host_name'] = self.last_hostname
            probes[i] = probe
        self.result[hop_num] = {'probes': probes}

    def start(self, *args):
        return self.result

class SRLAPIPatched(SRLAPI):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)
        gnmi_logger.setLevel(logging.CRITICAL + 1)

    def open(self):
        """Establish a connection using pygnmi"""
        try:
            # Read certs
            ssl_options = {}
            if self.tls_cert:
                ssl_options["certfile"] = self.tls_cert
            if self.tls_key:
                ssl_options["keyfile"] = self.tls_key
            if self.tls_ca:
                ssl_options["ca_certs"] = self.tls_ca
            elif self.insecure:
                logging.warning("Connecting without verifying TLS certificate (insecure=True). Not recommended for production.")
                ssl_options["insecure"] = True

            # pygnmi expects a tuple (host, port)
            self._client = gNMIclient(
                target=(self.hostname, self.gnmi_port),
                username=self.username,
                password=self.password,
                insecure=self.insecure,
                path_cert=self.tls_cert,
                path_key=self.tls_key,
                path_root=self.tls_ca,
                timeout=self.timeout,
                target_name_override=self.target_name if self.target_name else None,
            )
            self._client.connect()

        except Exception as e:
            logging.error(f"Error in Connection to {self.hostname} via gNMI: {e}")
            raise ConnectionException(e) from e

    def _gnmiGet(self, prefix, path, pathType):
        """
        Executes a gNMI Get request using pygnmi
        """
        try:
            if isinstance(path, (tuple,set)):
                paths = [p for p in path]
            elif isinstance(path, str):
                paths = [path]
            else:
                paths = path
            # paths = path if isinstance(path, list) else [path]
            get_args = {
                "path": paths,
                "encoding": self.encoding.lower(),  # pygnmi uses lowercase
                "datatype": pathType.lower(),      # e.g., config/state/all
            }
            if prefix:
                get_args["prefix"] = prefix

            response = self._client.get(**get_args)
            notifications = response.get("notification", [])
            return self._mergeToSingleDict(notifications)
        except gNMIException as gnmi_ex:
            if gnmi_ex.orig_exc.args[0].code == StatusCode.INVALID_ARGUMENT:
                return ""
            else:
                raise gnmi_ex
        except Exception as e:
            logging.error(f"Error executing gNMI Get: {e}")
            raise e

    def _mergeToSingleDict(self, notifications):
        """
        Merge pygnmi notifications into a single nested dict.
        Handles missing paths (e.g., from wildcard queries like interface[name=*]).
        """
        result = {}

        for notif in notifications:
            prefix = notif.get("prefix", "")
            updates = notif.get("update", [])

            for update in updates:
                # Handle case where update has no path (e.g., result of a wildcard query)
                if update.get("path") is None:
                    full_path = prefix.strip("/").split("/") if prefix else []
                else:
                    full_path = []
                    if prefix:
                        full_path.extend(prefix.strip("/").split("/"))
                    full_path.extend(update["path"].strip("/").split("/"))

                # If full_path is empty, set the whole result to the value
                if not full_path:
                    result = update["val"]
                    continue

                # Navigate and assign
                current = result
                for part in full_path[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[full_path[-1]] = update["val"]

        return result

class CustomSRLDriver(NokiaSRLDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        opt_args = {
            "target_name": hostname,
            "skip_verify": False,
            "insecure": False,
        }
        opt_args.update(optional_args)

        logging.basicConfig(
            filename="srlinux.log",  # Log file name
            level=logging.WARNING,  # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
            datefmt="%Y-%m-%d %H:%M:%S",  # Date format
        )

        ############### SUPER ###############
        """Constructor."""
        self.device = None
        self._metadata = None
        # still need to figure out why these variables are used
        self.config_session = None
        self.locked = False
        self.profile = ["srl"]
        self.platform = "srl"

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.private_candidate_name = None

        self._stub = None
        self._channel = None
        self.running_format = optional_args.get("running_format","json") if optional_args else "json"

        self.device = SRLAPIPatched(hostname, username, password, timeout=60, optional_args=optional_args)

        self.pending_commit = False
        # Whether to save changes to startup config, default False
        self.commit_mode = "save" if optional_args and optional_args.get("commit_save",False) else "now"
        self.tmp_cfgfile = None
        self.chkpoint_id = 0

        # super().__init__(hostname, username, password, timeout, opt_args)

    def ping(self, destination, source="", ttl=None, timeout=None, size=None, count=None, vrf=None):
        return super()._ping(destination, source, ttl, timeout, size, count, vrf)

    def traceroute(self, destination, source="", ttl=50, timeout=2, vrf=""):
        # Connection will timeout after 1 min, we need to make sure traceroute returns before timming out
        if ttl > 50:
            ttl = 50
        try:
            if not vrf:
                vrf = "default"
            command = "traceroute {} {} {}".format(
                destination,
                "-m {}".format(ttl) if ttl else "",
                "network-instance {}".format(vrf) if vrf else "",
            )
            output = self.device._jsonrpcRunCli([command])
            if "error" in output:
                return {
                    "error": output["error"]
                }
            if "result" not in output:
                return {
                    "error": "No result in output: {}".format(output)
                }
            result = output["result"][0]['text']
            if "* * *" in result:
                return {
                    'error': 'unknown host {}'.format(destination)
                }

            parser = Lark(TRACEROUTE_GRAMMAR, parser="lalr")
            tree = parser.parse(result)
            parsed = TracerouteTransformer().transform(tree)
            return {"success": parsed}
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

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
            path = ("/platform/chassis", "system/information", "system/name/host-name")
            interface_path = ("interface[name=*]",)
            pathType = "STATE"

            output = self.device._gnmiGet("", path, pathType)
            interface_output = self.device._gnmiGet("", interface_path, pathType)

            interface_list = [iface["name"] for iface in interface_output.get("srl_nokia-interfaces:interface", [])]

            # defining output variables
            uptime = -1.0
            version = ""
            hostname = ""
            serial_number = ""
            chassis_type = ""

            # getting system and platform information
            for key, value in output.items():
                if "system" in key and isinstance(value, dict):
                    for key_1, value_1 in value.items():
                        if "information" in key_1:
                            version = value_1.get("version")
                            uptime = value_1.get("uptime")
                            if uptime:
                                uptime = datetime.datetime.strptime(uptime, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
                            else:
                                current_time = datetime.datetime.strptime(value_1["current-datetime"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
                                last_boot = datetime.datetime.strptime(value_1["last-booted"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
                                uptime = current_time - last_boot if current_time and last_boot else -1.0

                        hostname = value.get("name", {}).get("host-name", "")

                if "platform" in key and isinstance(value, dict):
                    for key_1, value_1 in value.items():
                        if "chassis" in key_1:
                            chassis_type = value_1.get("type")
                            serial_number = value_1.get("serial-number")
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
                afi_safi = bgp_neighbor.get("afi-safi", None)
                if afi_safi is None:
                    ipv4_unicast = self._find_txt(bgp_neighbor, "ipv4-unicast")
                    if ipv4_unicast:
                        ipv4_unicast = eval(ipv4_unicast.replace("'", '"'))
                        prefix_limit.update(
                            {
                                "ipv4": {
                                    "sent_prefixes": convert(
                                        int,
                                        ipv4_unicast.get("sent-routes"),
                                        default=-1,
                                    ),
                                    "received_prefixes": convert(
                                        int,
                                        ipv4_unicast.get("received-routes"),
                                        default=-1,
                                    ),
                                    "accepted_prefixes": convert(
                                        int,
                                        ipv4_unicast.get("active-routes"),
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
                                        ipv6_unicast.get("sent-routes"),
                                        default=-1,
                                    ),
                                    "received_prefixes": convert(
                                        int,
                                        ipv6_unicast.get("received-routes"),
                                        default=-1,
                                    ),
                                    "accepted_prefixes": convert(
                                        int,
                                        ipv6_unicast.get("active-routes"),
                                        default=-1,
                                    ),
                                }
                            }
                        )
                else:
                    ipv4_unicast = next((x for x in afi_safi if x['afi-safi-name'] == 'srl_nokia-common:ipv4-unicast'), None)
                    ipv6_unicast = next((x for x in afi_safi if x['afi-safi-name'] == 'srl_nokia-common:ipv6-unicast'), None)
                    evpn = next((x for x in afi_safi if x['afi-safi-name'] == 'srl_nokia-common:evpn'), None)
                    if ipv4_unicast['admin-state'] == 'enable':
                        prefix_limit.update(
                            {
                                "ipv4": {
                                    "sent_prefixes": convert(
                                        int,
                                        ipv4_unicast.get('sent-routes', -1),
                                        default=-1,
                                    ),
                                    "received_prefixes": convert(
                                        int,
                                        ipv4_unicast.get('received-routes', -1),
                                        default=-1,
                                    ),
                                    "accepted_prefixes": convert(
                                        int,
                                        ipv4_unicast.get('active-routes', -1),
                                        default=-1,
                                    ),
                                    "rejected_prefixes": convert(
                                        int,
                                        ipv4_unicast.get('rejected-routes', -1),
                                        default=-1,
                                    ),
                                    "recieved_prefixes_whithdrawn_due_to_error": convert(
                                        int,
                                        ipv4_unicast.get('received-routes-withdrawn-due-to-error', -1),
                                        default=-1,
                                    ),
                                }
                            }
                        )
                    if ipv6_unicast['admin-state'] == 'enable':
                        prefix_limit.update(
                            {
                                "ipv6": {
                                    "sent_prefixes": convert(
                                        int,
                                        ipv6_unicast.get('sent-routes', -1),
                                        default=-1,
                                    ),
                                    "received_prefixes": convert(
                                        int,
                                        ipv6_unicast.get('received-routes', -1),
                                        default=-1,
                                    ),
                                    "accepted_prefixes": convert(
                                        int,
                                        ipv6_unicast.get('active-routes', -1),
                                        default=-1,
                                    ),
                                    "rejected_prefixes": convert(
                                        int,
                                        ipv6_unicast.get('rejected-routes', -1),
                                        default=-1,
                                    ),
                                    "recieved_prefixes_whithdrawn_due_to_error": convert(
                                        int,
                                        ipv6_unicast.get('received-routes-withdrawn-due-to-error', -1),
                                        default=-1,
                                    ),
                                }
                            }
                        )
                    if evpn['admin-state'] == 'enable':
                        prefix_limit.update(
                            {
                                "evpn": {
                                    "sent_prefixes": convert(
                                        int,
                                        evpn.get('sent-routes', -1),
                                        default=-1,
                                    ),
                                    "received_prefixes": convert(
                                        int,
                                        evpn.get('received-routes', -1),
                                        default=-1,
                                    ),
                                    "accepted_prefixes": convert(
                                        int,
                                        evpn.get('active-routes', -1),
                                        default=-1,
                                    ),
                                    "rejected_prefixes": convert(
                                        int,
                                        evpn.get('rejected-routes', -1),
                                        default=-1,
                                    ),
                                    "recieved_prefixes_whithdrawn_due_to_error": convert(
                                        int,
                                        evpn.get('received-routes-withdrawn-due-to-error', -1),
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
                system_date_time = value.get("current-datetime")
                if system_date_time:
                    system_date_time = datetime.datetime.strptime(system_date_time, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

            for network_instance in output["srl_nokia-network-instance:network-instance"]:
                instance_name = network_instance.get("name")
                router_id = network_instance.get("router-id")
                global_autonomous_system_number = network_instance.get("autonomous-system")
                bgp_neighbors.update({instance_name: {"router_id": router_id, "peers": {}}})
                protocols = network_instance.get("protocols")
                bgp_neighbors_list = protocols.get("srl_nokia-bgp:bgp", {}).get("neighbor", [])
                for bgp_neighbor in bgp_neighbors_list:
                    peer_ip = bgp_neighbor.get("peer-address")
                    if peer_ip:
                        local_as = bgp_neighbor.get("local-as")
                        explicit_peer_as = bgp_neighbor.get("peer-as")

                        local_as_number = -1
                        peer_as_number = (
                            explicit_peer_as
                            if explicit_peer_as
                            else global_autonomous_system_number
                        )
                        if local_as:
                            explicit_local_as_number = local_as.get("as-number")
                        local_as_number = (
                            explicit_local_as_number
                            if explicit_local_as_number
                            else global_autonomous_system_number
                        )
                        last_established = bgp_neighbor.get("last-established")
                        if last_established:
                            last_established = datetime.datetime.strptime(last_established, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
                        bgp_neighbors[instance_name]["peers"].update(
                            {
                                peer_ip: {
                                    "local_as": as_number(local_as_number),
                                    "remote_as": as_number(peer_as_number),
                                    "remote_id": peer_ip,
                                    "is_up": bgp_neighbor.get("session-state") == "established",
                                    "is_enabled": bgp_neighbor.get("admin-state") == "enable",
                                    "description": bgp_neighbor.get("description"),
                                    "uptime": convert(int, (system_date_time - last_established) if isinstance(last_established, float) else -1, default=-1),
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
                instance_name = network_instance.get("name")
                router_id = network_instance.get("router-id")
                global_autonomous_system_number = network_instance.get("autonomous-system")

                bgp_neighbors_list = network_instance.get("protocols", {}).get("srl_nokia-bgp:bgp", {}).get("neighbor", [])
                bgp_neighbor_detail[instance_name] = {}
                for bgp_neighbor in bgp_neighbors_list:
                    peer_ip = bgp_neighbor.get("peer-address")
                    if peer_ip:
                        if neighbor_address and not neighbor_address == peer_ip:
                            continue
                        local_as = bgp_neighbor.get("local-as")
                        explicit_peer_as = bgp_neighbor.get("peer-as")
                        local_as_number = -1
                        peer_as_number = (
                            explicit_peer_as
                            if explicit_peer_as
                            else global_autonomous_system_number
                        )

                        if local_as:
                            explicit_local_as_number = local_as.get("as-number")
                        local_as_number = (
                            explicit_local_as_number
                            if explicit_local_as_number
                            else global_autonomous_system_number
                        )
                        transport = bgp_neighbor.get("transport")
                        local_address = ""
                        if transport:
                            local_address = transport.get("local-address")
                        timers = bgp_neighbor.get("timers")
                        sent_messages = bgp_neighbor.get("sent-messages")
                        received_messages = bgp_neighbor.get("received-messages")

                        ipv4_unicast = next((x for x in bgp_neighbor['afi-safi'] if x['afi-safi-name'] == 'srl_nokia-common:ipv4-unicast'), None)
                        active_ipv4 = ipv4_unicast.get('active-routes', -1)
                        received_ipv4 = ipv4_unicast.get('received-routes', -1)
                        suppressed_ipv4 = ipv4_unicast.get('rejected-routes', -1)
                        advertised_ipv4 = ipv4_unicast.get('sent-routes', -1)
                        evpn = next((x for x in bgp_neighbor['afi-safi'] if x['afi-safi-name'] == 'srl_nokia-common:evpn'), None)
                        active_evpn = evpn.get('active-routes', -1)
                        received_evpn = evpn.get('received-routes', -1)
                        suppressed_evpn = evpn.get('rejected-routes', -1)
                        advertised_evpn = evpn.get('sent-routes', -1)
                        ipv6_unicast = next((x for x in bgp_neighbor['afi-safi'] if x['afi-safi-name'] == 'srl_nokia-common:ipv6-unicast'), None)
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
                            "up": bgp_neighbor.get("session-state") == "established",
                            "local_as": as_number(local_as_number),
                            "remote_as": as_number(peer_as_number),
                            "router_id": router_id,
                            "local_address": local_address,
                            "routing_table": bgp_neighbor.get("peer-group"),
                            "local_address_configured": False if local_address else True,
                            "local_port": convert(
                                int,
                                transport.get("local-port"),
                                default=-1,
                            )
                            if transport
                            else -1,
                            "remote_address": peer_ip,
                            "remote_port": convert(
                                int,
                                transport.get("remote-port"),
                                default=-1,
                            ),
                            "multihop": False,  # Not yet supported in SRLinux
                            "multipath": False,  # Not yet supported in SRLinux
                            "remove_private_as": False,  # Not yet supported in SRLinux
                            "import_policy": bgp_neighbor.get("import-policy"),
                            "export_policy": bgp_neighbor.get("export-policy"),
                            "input_messages": convert(
                                int,
                                received_messages.get("total-messages"),
                                default=-1,
                            ),
                            "output_messages": convert(
                                int,
                                sent_messages.get("total-messages"),
                                default=-1,
                            ),
                            "input_updates": convert(
                                int,
                                received_messages.get("total-updates"),
                                default=-1,
                            ),
                            "output_updates": convert(
                                int,
                                sent_messages.get("total-updates"),
                                default=-1,
                            ),
                            "messages_queued_out": convert(
                                int,
                                sent_messages.get("queue-depth"),
                                default=-1,
                            ),
                            "connection_state": bgp_neighbor.get("session-state"),
                            "previous_connection_state": bgp_neighbor.get("last-state"),
                            "last_event": bgp_neighbor.get("last-event"),
                            "suppress_4byte_as": False,  # Not yet supported in SRLinux
                            "local_as_prepend": convert(
                                bool,
                                local_as.get("prepend-local-as"),
                                default=False,
                            ),
                            "holdtime": convert(
                                int,
                                timers.get("hold-time"),
                                default=-1,
                            ),
                            "configured_holdtime": convert(
                                int,
                                timers.get("negotiated-hold-time"),
                                default=-1,
                            ),
                            "keepalive": convert(
                                int,
                                timers.get("keepalive-interval"),
                                default=-1,
                            ),
                            "configured_keepalive": convert(
                                int,
                                timers.get("negotiated-keepalive-interval",),
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
                neighbor_list = ip_dict.get("neighbor")
                if neighbor_list:
                    for neighbor in neighbor_list:
                        ipv4_address = ""
                        ipv6_address = ""
                        timeout = -1.0
                        reachable_time = -1.0
                        if is_ipv4:
                            ipv4_address = neighbor.get("ipv4-address")
                            timeout = convert(
                                float, ip_dict.get("timeout"), default=-1.0
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
                            ipv6_address = neighbor.get("ipv6-address")
                            reachable_time = convert(
                                float,
                                ip_dict.get("reachable-time"),
                                default=-1.0,
                            )
                        arp_table.append(
                            {
                                "interface": sub_interface_name,
                                "mac": neighbor.get("link-layer-address"),
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
                    subinterface_list = vrf.get("interface")
                    for dictionary in subinterface_list:
                        if "name" in dictionary.keys():
                            subinterface_names.append(dictionary.get("name"))

            interface_path = {"interface[name=*]"}
            interface_output = self.device._gnmiGet("", interface_path, pathType)

            for interface in interface_output.get("srl_nokia-interfaces:interface", []):
                interface_name = interface.get("name")
                if not interface_name:
                    continue

                for dictionary in interface.get("subinterface", []):
                    sub_interface_name = dictionary.get("name")
                    if sub_interface_name in subinterface_names:
                        ipv4_arp_dict = dictionary.get("ipv4", {}).get("srl_nokia-interfaces-nbr:arp")
                        if ipv4_arp_dict:
                            _find_neighbors(True, ipv4_arp_dict)

                        ipv6_neighbor_dict = dictionary.get("ipv6", {}).get("srl_nokia-if-ip-nbr:neighbor-discovery")
                        if ipv6_neighbor_dict:
                            _find_neighbors(False, ipv6_neighbor_dict)

            return arp_table
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_route_to(self, destination='', protocol='', longer=False):
        """
        :return:Returns a dictionary of dictionaries containing details of all available routes to a destination.
        """
        try:
            path = {"/network-instance"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            dpath = {"/system/information/current-datetime"}
            doutput = self.device._gnmiGet("", dpath, "STATE")
            ctdatetime = self._getObj(doutput,
                                      *['srl_nokia-system:system', 'srl_nokia-system-info:information', 'current-datetime'],
                                      default=None)
            interfaces = self._getObj(output, *['srl_nokia-network-instance:network-instance'], default=[])
            route_data = {}
            for i in interfaces:
                routes = self._getObj(i, *["route-table", "srl_nokia-ip-route-tables:ipv4-unicast", "route"], default=[])
                next_hop_groups = self._getObj(i, *["route-table", "srl_nokia-ip-route-tables:next-hop-group"], default=[])
                next_hops = self._getObj(i, *["route-table", "srl_nokia-ip-route-tables:next-hop"], default=[])
                name = self._getObj(i, *["name"])
                for r in routes:
                    if "next-hop-group" not in r:
                        continue
                    next_hop_group_id = r["next-hop-group"]
                    next_hop_group = [n for n in next_hop_groups if n["index"] == next_hop_group_id]
                    next_hop_group = next_hop_group[0]  # definitely this will be present . list cannot be empty
                    next_hop_ids = [n["next-hop"] for n in next_hop_group["next-hop"]]

                    ct_next_hops = [n for n in next_hops if n["index"] in next_hop_ids]
                    ct_next_hops_data = []
                    for next_hop in ct_next_hops:
                        ip_address = self._getObj(next_hop, *["ip-address"])
                        subinterface = self._getObj(next_hop, *["subinterface"])
                        if ctdatetime and self._getObj(r, *["last-app-update"], default=None):
                            ctdatetime_obj = datetime.datetime.strptime(ctdatetime, "%Y-%m-%dT%H:%M:%S.%fZ")
                            last_app_date = datetime.datetime.strptime(r["last-app-update"], "%Y-%m-%dT%H:%M:%S.%fZ")
                            age = int((ctdatetime_obj - last_app_date).total_seconds())
                        else:
                            age = -1
                        ct_protocol = str(r["route-owner"]).split(":")[-1]
                        data = {
                            "protocol": ct_protocol,
                            "current_active": self._getObj(r, *["active"], default=False),
                            "last_active": False,
                            "age": age,
                            "next_hop": ip_address,
                            "outgoing_interface": subinterface,
                            "selected_next_hop": True if ip_address else False,
                            "preference": self._getObj(r, *["preference"], default=-1),
                            "inactive_reason": "",
                            "routing_table": name,
                        }
                        if "bgp" in r["route-owner"]:
                            bgp_protocol = self._getObj(i, *["protocols", "srl_nokia-bgp:bgp"], default={})
                            afi_safi = i.get("srl_nokia-rib-bgp:bgp-rib", {}).get("afi-safi", {})
                            ipv4_unicast = list(filter(lambda x: x['afi-safi-name'] == 'srl_nokia-common:ipv4-unicast', afi_safi))[0]
                            bgp_rib_routes = ipv4_unicast.get("ipv4-unicast", {}).get("local-rib", {}).get("route", [])
                            # bgp_rib_routes = self._getObj(i, *["srl_nokia-rib-bgp:bgp-rib", "ipv4-unicast", "local-rib",
                            #                                    "routes"], default=[])
                            bgp_rib_attrsets = self._getObj(i, *["srl_nokia-rib-bgp:bgp-rib", "attr-sets", "attr-set"],
                                                            default=[])
                            neighbor = [b for b in bgp_protocol["neighbor"] if b["peer-address"] == ip_address]
                            neighbor = neighbor[0]  # exactly one neighbor will be present if it is bgp
                            rib_route = [rr for rr in bgp_rib_routes if
                                         rr["prefix"] == r["ipv4-prefix"] and rr["neighbor"] == ip_address and rr[
                                             "origin-protocol"] == "srl_nokia-common:bgp"]
                            rib_route = rib_route[0]
                            attr_id = rib_route["attr-id"]
                            att_set = [a for a in bgp_rib_attrsets if a["index"] == attr_id][0]
                            data.update({
                                "protocol_attributes": {
                                    "local_as": self._getObj(bgp_protocol, *["autonomous-system"], default=-1),
                                    "remote_as": self._getObj(neighbor, *["peer-as"], default=-1),
                                    "peer_id": self._getObj(neighbor, *["peer-address"]),
                                    "as_path": str(self._getObj(att_set, *["as-path", "segment", 0, "member", 0])),
                                    "communities": self._getObj(att_set, *["communities", "community"], default=[]),
                                    "local_preference": self._getObj(att_set, *["local-pref"], default=-1),
                                    "preference2": -1,
                                    "metric": self._getObj(r, *["metric"], default=-1),
                                    "metric2": -1
                                }
                            })
                        if "isis" in r["route-owner"]:
                            isis_protocol = self._getObj(i, *["protocols", "srl_nokia-isis:isis", "instance"])[0]
                            level = self._getObj(isis_protocol, *["level", 0, "level-number"], default=-1)
                            data.update({
                                "protocol_attributes": {
                                    "level": level
                                }
                            })
                        ct_next_hops_data.append(data)
                    if destination and (
                            destination == r["ipv4-prefix"] or destination == str(r["ipv4-prefix"]).split("/")[0]):
                        return {
                            r["ipv4-prefix"]: ct_next_hops_data
                        }
                    route_data.update({
                        r["ipv4-prefix"]: ct_next_hops_data
                    })
            if protocol:
                route_data_filtered = {}
                for ipv4_prefix, nhs in route_data.items():
                    next_hop_filtered = [n for n in nhs if n["protocol"] == protocol]
                    if next_hop_filtered:
                        route_data_filtered.update({
                            ipv4_prefix: next_hop_filtered
                        })
                return route_data_filtered
            if destination:  # if destination was present , it should not reach here, rather returned earlier.
                return {}
            return route_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_ethernet_segments(self):
        path_spec = {
            "path": f"/system/network-instance/protocols/evpn/ethernet-segments",
            "jmespath": '"system/network-instance/protocols/evpn/ethernet-segments"."bgp-instance"[]."ethernet-segment"[].{name:name, esi:esi, "mh-mode":"multi-homing-mode",\
                oper:"oper-state",itf:interface[]."ethernet-interface"|join(\' \',@), "ni-peers":association."network-instance"[]."_ni_peers"|join(\', \',@) }',
            "datatype": "STATE",
        }

        def set_es_peers(resp):
            res = []
            for bgp_inst in (
                # resp[0]
                # .get("system/network-instance/protocols/evpn/ethernet-segments", {})
                # .get("bgp-instance", [])
                resp.get("srl_nokia-system:system", {}).get("srl_nokia-system-network-instance:network-instance", {}).get("protocols", {}).get("evpn", {}).get("srl_nokia-system-network-instance-bgp-evpn-ethernet-segments:ethernet-segments", {}).get("bgp-instance", [])
                # resp['srl_nokia-system:system']['srl_nokia-system-network-instance:network-instance']['protocols']['evpn']['srl_nokia-system-network-instance-bgp-evpn-ethernet-segments:ethernet-segments']['bgp-instance']

            ):
                for es in bgp_inst.get("ethernet-segment", []):
                    es['bgp_instance'] = bgp_inst['id']
                    if not "association" in es:
                        es["association"] = {}
                    if not "network-instance" in es["association"]:
                        es["association"]["network-instance"] = []
                    for vrf in es["association"]["network-instance"]:
                        es_peers = (
                            vrf["bgp-instance"][0]
                            .get("computed-designated-forwarder-candidates", {})
                            .get("designated-forwarder-candidate", [])
                        )
                        vrf["_peers"] = " ".join(
                            (
                                f"{peer['address']}(DF)"
                                if peer["designated-forwarder"]
                                else peer["address"]
                            )
                            for peer in es_peers
                        )
                        vrf["_ni_peers"] = f"{vrf['name']}:[{vrf['_peers']}]"
                    res.append(es)
            return res

        system_features = self.device._gnmiGet(prefix="", path=("/system/features",), pathType="STATE")
        if (not "evpn" in system_features['srl_nokia-system:system']['features']):
            return {"es": []}
        resp = self.device._gnmiGet(prefix="", path=(path_spec.get("path", ""),), pathType=path_spec["datatype"])
        # set_es_peers(resp)
        # res = jmespath.search(path_spec["jmespath"], resp[0])
        return set_es_peers(resp)

    def get_link_agregation_groups(self, lag_id: str = "*"):
        path_spec = {
            "path": (f"/openconfig/interfaces/interface[name=lag{lag_id}]", f"/openconfig/lacp/interfaces/interface[name=lag{lag_id}]"),
            "datatype": "STATE",
        }
        path_spec['jmespath_interfaces'] = '"openconfig-interfaces:interfaces"."interface"[].{\
            name: name,\
            mtu: state.mtu,\
            lag_type: "openconfig-if-aggregate:aggregation".state."lag-type",\
            min_links: "openconfig-if-aggregate:aggregation".state."min-links",\
            lag_speed: "openconfig-if-aggregate:aggregation".state."lag-speed",\
            members: "openconfig-if-aggregate:aggregation".state.member[]\
        }'
        path_spec['jmespath_lacp'] = '"openconfig-lacp:lacp"."interfaces"."interface"[].{\
            name: name,\
            lacp_interval: state.interval,\
            lacp_mode: state."lacp-mode",\
            system_id_mac: state."system-id-mac",\
            system_id_priority: state."system-priority",\
            members: members.member[].{\
                interface: state.interface,\
                activity: state.activity,\
                timeout: state.timeout,\
                synchronization: state.synchronization,\
                aggregatable: state.aggregatable,\
                collecting: state.collecting,\
                distributing: state.distributing,\
                system_id: state."system-id",\
                key: state."oper-key",\
                partner_id: state."partner-id",\
                partner_key: state."partner-key",\
                port_number: state."port-num",\
                partner_port_number: state."partner-port-num"\
            }\
        }'

        resp = self.device._gnmiGet(prefix="", path=path_spec["path"], pathType=path_spec["datatype"])

        interfaces = jmespath.search(path_spec["jmespath_interfaces"], resp)
        if interfaces is None:
            return []
        lacp = jmespath.search(path_spec["jmespath_lacp"], resp)

        for interface in interfaces:
            for i in lacp:
                if i['name'] == interface['name']:
                    interface.update(i)
                    break

        return interfaces

    def get_tunnel_table(self):
        path = "/network-instance[name=*]/tunnel-table"
        ret = self.device._gnmiGet(prefix='', path=path, pathType="state")

        tunnels = []
        vrfs = ret['srl_nokia-network-instance:network-instance']
        for vrf in vrfs:
            tunnel_table = vrf.get('tunnel-table', {})
            for tunnel in tunnel_table['srl_nokia-tunnel-tables:ipv4'].get('tunnel', []) + tunnel_table['srl_nokia-tunnel-tables:ipv6'].get('tunnel', []):
                tunnel_data = {
                    'ipv4-prefix': tunnel.get('ipv4-prefix'),
                    'ipv6-prefix': tunnel.get('ipv6-prefix'),
                    'type': tunnel.get('type').replace('srl_nokia-common:', ''),
                    'id': tunnel.get('id'),
                    'protocol': tunnel.get('encapsulation-type'),
                    'preference': tunnel.get('preference'),
                    'status': tunnel['fib-programming'].get('status'),
                }
                if 'fib-programming' in tunnel:
                    tunnel_data['status'] = tunnel['fib-programming'].get('status')
                if 'vxlan' in tunnel:
                    tunnel_data['vxlan'] = {
                        'destination-address': tunnel['vxlan'].get('destination-address'),
                        'source-address': tunnel['vxlan'].get('source-address'),
                        'time-to-live': tunnel['vxlan'].get('time-to-live'),
                    }
                tunnels.append(tunnel_data)

        return tunnels

    def get_interface_counters(self):
        path = "/interfaces/interface"
        prefix = "openconfig:"
        ret = self.device._gnmiGet(prefix=prefix, path=path, pathType="state")
        counters = {}
        for interface in ret['interfaces']['interface']:
            val = interface['state']
            counters[val['name']] = val['counters']

        return counters

    def _remove_prefix(self, d, prefix):
        return {k[len(prefix):] if k.startswith(prefix) else k: v for k, v in d.items()}


def dictToList(self, aDict):
        keys_to_update = {}  # Store new keys to add after iteration
        keys_to_delete = []  # Store keys to delete after iteration

        for key in list(aDict.keys()):  # Use list() to avoid modifying during iteration
            if key.startswith("___"):
                keys_to_update[key[3:]] = [
                    self._dictToList(val) if isinstance(val, dict) else val
                    for val in aDict[key].values()
                ]
                keys_to_delete.append(key)  # Mark for deletion
            elif isinstance(aDict[key], dict):
                aDict[key] = self._dictToList(aDict[key])

        # Apply updates outside the loop
        aDict.update(keys_to_update)
        for key in keys_to_delete:
            del aDict[key]

        return aDict

SRLAPI._dictToList = dictToList
