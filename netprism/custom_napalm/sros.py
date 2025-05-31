from napalm_sros.sros import NokiaSROSDriver
import napalm.base.constants as C
from napalm.base.helpers import convert
import traceback
import logging
from lark import Lark, Transformer, v_args
from pygnmi.client import gNMIclient
from copy import deepcopy
from ncclient.xml_ import to_ele
from napalm_sros.nc_filters import GET_ROUTE_TO
import re

TRACEROUTE_GRAMMAR = r"""
start: (line)* [TRAILING_GARBAGE]

line: hop
    | garbage_line_rule

hop: HOP_NUM ping ping ping NEWLINE?

// PRIORITIES: Higher number = higher priority
RTT.3: /\d+(\.\d+)?\s*[a-z]+/
IP.2: "(" /[0-9.]+/ ")"
HOP_NUM.1: /\d+(?=\s)/
hostname: /[^\s()]+/

garbage_line_rule: GARBAGE_LINE_TERMINATED
GARBAGE_LINE_TERMINATED: /[^\n]*\n/
TRAILING_GARBAGE: /[^\r\n]+/


ping: lost_ping | full_ping | simple_ping

lost_ping: "*"
full_ping: hostname IP RTT
simple_ping: RTT

%import common.NEWLINE
%import common.WS
%ignore WS
"""

log = logging.getLogger(__file__)

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
                probe['rtt'] = None
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


class CustomSROSDriver(NokiaSROSDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):

        opt_args = {
            "target_name": hostname,
            "skip_verify": False,
            "insecure": False,
        }
        opt_args.update(optional_args)

        logging.basicConfig(
            filename="sros.log",  # Log file name
            level=logging.WARNING,  # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
            datefmt="%Y-%m-%d %H:%M:%S",  # Date format
        )

        self.gnmi = None
        self.gnmi_host = optional_args.get("gnmi_host", hostname)
        self.gnmi_port = optional_args.get("gnmi_port", 57400)
        self.gnmi_tls = optional_args.get("gnmi_tls", not opt_args['insecure'])

        super().__init__(hostname, username, password, timeout, opt_args)
        self.optional_args = opt_args
        self.insecure = optional_args.get("insecure", False)
        self.tls_ca = optional_args.get("tls_ca", "")
        self.tls_cert = optional_args.get("tls_cert", "")
        self.tls_key = optional_args.get("tls_key", "")

    def open(self):
        super().open()
        if not self.gnmi_tls:
            logging.warning("Connecting without verifying TLS certificate (insecure=True). Not recommended for production.")

        try:
            self.gnmi = gNMIclient(
                target=(self.gnmi_host, self.gnmi_port),
                username=self.username,
                password=self.password,
                path_cert=self.tls_cert,
                path_key=self.tls_key,
                path_root=self.tls_ca,
                insecure=not self.gnmi_tls,
                timeout=self.timeout,
            )
            self.gnmi.connect()
            log.info("gNMI session established")
        except Exception as e:
            log.error(f"Failed to establish gNMI session: {e}")
            self.gnmi = None

    def close(self):
        if self.gnmi:
            try:
                self.gnmi.close()
                log.info("gNMI session closed")
            except Exception as e:
                log.warning(f"Failed to close gNMI session cleanly: {e}")

        super().close()

    def gnmi_get(self, prefix=None, path=None, encoding="json_ietf", datatype="all"):
        """
        Perform a gNMI Get request.

        :param prefix: Optional string prefix to apply to all paths.
        :param path: A string path or list of string paths to fetch.
        :param encoding: Encoding type (default: "json_ietf").
        :param datatype: gNMI data type ("all", "config", "state", etc.).
        :return: Decoded dictionary with gNMI response or None on error.
        """
        if self.gnmi is None:
            log.error("gNMI session is not established")
            return None

        if path is None:
            log.error("gNMI get requires a path")
            return None

        if isinstance(path, str):
            path = [path]

        try:
            response = self.gnmi.get(
                prefix=prefix,
                path=path,
                encoding=encoding,
                datatype=datatype,
            )
            # pygnmi returns {"notification": [...]}
            updates = response.get("notification", [])
            updates = [up['update'] for up in updates][0]
            return updates
            # return [(u['path'], u['val']) for u in updates]
            # return [{u['path']: u['val']} for u in updates]
        except Exception as e:
            log.error(f"gNMI get request failed: {e}")
            return None

    def _remove_prefix(self, d, prefix):
        return {k[len(prefix):] if k.startswith(prefix) else k: v for k, v in d.items()}

    def get_ethernet_segments(self):
        path = '/state/service/system/bgp/evpn/ethernet-segment'
        prefix = 'openconfig:'
        ret = self.gnmi_get(prefix=prefix, path=path, encoding='json_ietf', datatype='state')
        ess = [self._remove_prefix(es['val'], "nokia-state:") for es in ret if 'val' in es]
        
        output = []
        for es in ess:
            # Extract relevant data
            data = {
                'name': es['ethernet-segment-name'],
                'esi': hex_to_colon_separated(es['oper-esi']),
                'multi-homing-mode': es['multi-homing-oper-state'],
                # 'interface': None,
                '_ni_peers': None
            }

            for evi in es.get('evi', []):
                tmp = deepcopy(data)
                ips = [candidate['ip-address'] for candidate in evi['df-candidates']['ip-address']]
                tmp['_ni_peers'] = f"evi-{evi['id']}:[{' '.join(ips)}]"

                output.append(tmp)

        return output

    def get_link_agregation_groups(self):
        raise NotImplementedError

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """
        timeout should be in the range 10..60000
        """
        try:
            traceroute = {}
            if timeout < 10 :
                timeout = 10
            cmd = ""
            if source and vrf:
                cmd = "traceroute {d1} wait {d2} ttl {d3} source-address {d4} router-instance {d5}"
            elif not source and not vrf:
                cmd = "traceroute {d1} wait {d2} ttl {d3}"
            elif source:
                cmd = "traceroute {d1} wait {d2} ttl {d3} source-address {d4}"
            elif vrf:
                cmd = "traceroute {d1} wait {d2} ttl {d3} router-instance {d5}"
            cmd = cmd.format(
                d1=destination, d2=str(timeout), d3=str(ttl), d4=source, d5=vrf,
            )
            command = [
                "/environment progress-indicator admin-state disable",
                cmd,
            ]
            buff = self._perform_cli_commands(command, True, no_more=True)

            parser = Lark(TRACEROUTE_GRAMMAR, parser="lalr")
            tree = parser.parse(buff)
            parsed = TracerouteTransformer().transform(tree)
            return {"success": parsed}

        except Exception as e:
            print("Error in method traceroute : {}".format(e))
            log.error("Error in method traceroute : %s" % traceback.format_exc())
            traceroute.update({"error": e})
            return traceroute

    def get_tunnel_table(self):
        path = "/state/router/tunnel-table/ipv4/tunnel"
        prefix = "openconfig:"
        ret = self.gnmi_get(prefix=prefix, path=path, encoding="json_ietf", datatype="state")
        # tunnels = [tunnel[1] for tunnel in ret]
        # tunnels = [self._remove_prefix(tunnel, "nokia-state:") for tunnel in tunnels]

        tunnels = [self._remove_prefix(tunnel['val'], "nokia-state:") for tunnel in ret if 'val' in tunnel]
        return tunnels
    
    def get_interface_counters(self):
        path = "/interfaces/interface"
        prefix = "openconfig:"
        ret = self.gnmi_get(prefix=prefix, path=path, encoding="json_ietf", datatype="state")
        counters = {}
        for interface in ret:
            val = interface['val']['openconfig-interfaces:state']
            counters[val['name']] = val['counters']

        return counters
    
    def get_route_to(self, destination="", protocol="", longer=False):
        """
        Returns a dictionary of dictionaries containing details of all available routes to a destination.

        Parameters:
        destination – The destination prefix to be used when filtering the routes.
        (optional) (protocol) – Retrieve the routes only for a specific protocol.
        (optional) – Retrieve more specific routes as well.
        Each inner dictionary contains the following fields:

            protocol (string)
            current_active (True/False)
            last_active (True/False)
            age (int)
            next_hop (string)
            outgoing_interface (string)
            selected_next_hop (True/False)
            preference (int)
            inactive_reason (string)
            routing_table (string)
            protocol_attributes (dictionary)
            protocol_attributes is a dictionary with protocol-specific information, as follows:
            BGP
                local_as (int)
                remote_as (int)
                peer_id (string)
                as_path (string)
                communities (list)
                local_preference (int)
                preference2 (int)
                metric (int)
                metric2 (int)
            ISIS:
                level (int)
        """

        # helper functions
        try:
            route_to_dict = {}

            def _get_protocol_attributes(router_name, local_protocol):
                # destination needs to be with prefix
                command = f"/show router {router_name} route-table {destination} protocol {local_protocol} extensive all"
                output = self._perform_cli_commands([command], True, no_more=True)
                destination_address_with_prefix = ""
                next_hop_once = False
                next_hop = ""
                age = ""
                preference = ""
                for item_1 in re.split("\n|\r", output):
                    if "Dest Prefix" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        destination_address_with_prefix = row_1_list[1]
                        route_to_dict.update(
                            {
                                row_1_list[1]: [
                                    {
                                        "routing_table": router_name,
                                        "protocol": local_protocol,
                                        "last_active": False,
                                        "inactive_reason": "",
                                    }
                                ]
                            }
                        )
                    elif "Age" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        if "d" in row_1_list[1]:
                            time_string = re.split("d|h|m", row_1_list[1])
                        else:
                            time_string = re.split("h|m|s", row_1_list[1])
                        age = (
                            (int(time_string[0]) * 86400)
                            + (int(time_string[1]) * 60 * 60)
                            + (int(time_string[2]) * 60)
                        )
                        for d in route_to_dict[destination_address_with_prefix]:
                            d.update({"age": age})
                    elif "Preference" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        preference = row_1_list[1]
                        for d in route_to_dict[destination_address_with_prefix]:
                            d.update({"preference": convert(int, preference, default=-1)})
                    elif "Active" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        for d in route_to_dict[destination_address_with_prefix]:
                            if next_hop_once:
                                if d.get("next_hop") == next_hop:
                                    d.update(
                                        {
                                            "current_active": True
                                            if row_1_list[1] is True
                                            else False
                                        }
                                    )
                            else:
                                d.update(
                                    {
                                        "current_active": True
                                        if row_1_list[1] is True
                                        else False
                                    }
                                )
                    elif "Next-Hop" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        _sel = self.ipv4_address_re.search(row_1_list[1])
                        temp_2_dict = {"selected_next_hop": bool(_sel)}
                        if "Indirect" in item_1:
                            if next_hop_once:
                                next_hop = row_1_list[1]
                                route_to_dict[destination_address_with_prefix].append(
                                    {
                                        "routing_table": router_name,
                                        "protocol": protocol,
                                        "next_hop": row_1_list[1],
                                        "age": age,
                                        "preference": convert(int, preference, default=-1),
                                        "last_active": False,  # default value as SROS does not have this value
                                        "inactive_reason": "",
                                    }
                                )
                                for d in route_to_dict[destination_address_with_prefix]:
                                    if d.get("next_hop") == next_hop:
                                        d.update(temp_2_dict)
                            else:
                                for d in route_to_dict[destination_address_with_prefix]:
                                    d.update({"next_hop": row_1_list[1]})
                                    d.update(temp_2_dict)
                                next_hop_once = True
                                next_hop = row_1_list[1]
                        elif "Resolving" in item_1:
                            for d in route_to_dict[destination_address_with_prefix]:
                                if d.get("next_hop") == next_hop:
                                    d.update(temp_2_dict)
                                    d.update({"next_hop": row_1_list[1]})
                            next_hop = row_1_list[1]
                        else:
                            for d in route_to_dict[destination_address_with_prefix]:
                                d.update({"next_hop": row_1_list[1]})
                                d.update(temp_2_dict)
                            next_hop_once = True
                            next_hop = row_1_list[1]
                    elif "Interface" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        for d in route_to_dict[destination_address_with_prefix]:
                            if d.get("next_hop") == next_hop:
                                d.update({"outgoing_interface": row_1_list[1]})
                    elif "Metric" in item_1:
                        if local_protocol == "bgp":
                            row_1 = item_1.strip()
                            row_1_list = row_1.split(": ")
                            for d in route_to_dict[destination_address_with_prefix]:
                                if d.get("next_hop") == next_hop:
                                    # Update BGP protocol attributes dictionary
                                    d.update(
                                        {
                                            "protocol_attributes": {
                                                "metric": convert(
                                                    int, row_1_list[1], default=-1
                                                ),
                                                "metric2": -1,  # default value as SROS does not have this
                                                "preference2": convert(
                                                    int, preference, default=-1
                                                ),
                                            }
                                        }
                                    )

            # Method for extracting BGP protocol attributes from router
            def _get_bgp_protocol_attributes(router_name):
                destination_address_with_prefix = ""

                for k, v in route_to_dict.items():
                    destination_address_with_prefix = k
                if destination_address_with_prefix:
                    # protocol attributes local_as, as_path, local_preference
                    cmd = f"/show router {router_name} bgp routes {destination_address_with_prefix} detail"
                    buff_1 = self._perform_cli_commands( [cmd], True, no_more=True )

                    for d in route_to_dict[destination_address_with_prefix]:
                        next_hop = d.get("next_hop")

                        # protocol attributes peer_id and remote_as
                        match_router = False
                        for bgp_neighbor in result.xpath(
                            "state_ns:state/state_ns:router/state_ns:bgp/state_ns:neighbor",
                            namespaces=self.nsmap,
                        ):
                            ip_address = self._find_txt(
                                bgp_neighbor, "state_ns:ip-address", namespaces=self.nsmap
                            )
                            if ip_address == next_hop:
                                match_router = True
                                d["protocol_attributes"].update(
                                    {
                                        "peer_id": self._find_txt(
                                            bgp_neighbor,
                                            "state_ns:statistics/state_ns:peer-identifier",
                                            namespaces=self.nsmap,
                                        ),
                                        "remote_as": convert(
                                            int,
                                            self._find_txt(
                                                bgp_neighbor,
                                                "state_ns:statistics/state_ns:peer-as",
                                                namespaces=self.nsmap,
                                            ),
                                            default=-1,
                                        ),
                                    }
                                )
                                # update bgp protocol for protocol attributes local_as, as_path, local_preference
                                _update_bgp_protocol_attributes(buff_1, d)
                                break
                        if not match_router:
                            for vprn_bgp_neighbor in result.xpath(
                                "state_ns:state/state_ns:service/state_ns:vprn/state_ns:bgp/state_ns:neighbor",
                                namespaces=self.nsmap,
                            ):
                                ip_address = self._find_txt(
                                    vprn_bgp_neighbor,
                                    "state_ns:ip-address",
                                    namespaces=self.nsmap,
                                )
                                if ip_address == next_hop:
                                    d["protocol_attributes"].update(
                                        {
                                            "peer_id": self._find_txt(
                                                vprn_bgp_neighbor,
                                                "state_ns:statistics/state_ns:peer-identifier",
                                                namespaces=self.nsmap,
                                            ),
                                            "remote_as": self._find_txt(
                                                vprn_bgp_neighbor,
                                                "state_ns:statistics/state_ns:peer-as",
                                                namespaces=self.nsmap,
                                            ),
                                        }
                                    )
                                    # update bgp protocol for protocol attributes local_as, as_path, local_preference
                                    _update_bgp_protocol_attributes(buff_1, d)
                                    break

            def _update_bgp_protocol_attributes(buff_1, d):
                modified_attributes = False
                for item_1 in buff_1.split("\n"):
                    if "Modified Attributes" in item_1:
                        modified_attributes = True
                        continue
                    if "Local AS" in item_1:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(":")
                        d["protocol_attributes"].update(
                            {"local_as": convert(int, row_1_list[3], default=-1)}
                        )
                    elif "AS-Path" in item_1 and modified_attributes:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        d["protocol_attributes"].update({"as_path": row_1_list[1]})
                        modified_attributes = False
                    elif "Local Pref." in item_1 and modified_attributes:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        d["protocol_attributes"].update(
                            {
                                "local_preference": convert(
                                    int, row_1_list[1].split(" ")[0], default=-1
                                )
                            }
                        )
                    elif "Community" in item_1 and modified_attributes:
                        row_1 = item_1.strip()
                        row_1_list = row_1.split(": ")
                        multiple_community = row_1_list[1].split(" ")
                        d["protocol_attributes"].update({"communities": multiple_community})

            # Method for extracting ISIS protocol attributes from router
            def _get_isis_protocol_attributes(router_name):
                destination_address_with_prefix = ""
                for k, v in route_to_dict.items():
                    destination_address_with_prefix = k
                if destination_address_with_prefix:
                    for d in route_to_dict[destination_address_with_prefix]:
                        d.update({"protocol_attributes": {}})
                    command = f"/show router {router_name} isis routes ip-prefix-prefix-length {destination_address_with_prefix}"
                    buff_1 = self._perform_cli_commands([command], True, no_more=True)
                    prev_row = ""
                    for item_1 in buff_1.split("\n"):
                        if destination_address_with_prefix in item_1 or prev_row:
                            if "# show" in item_1 or item_1 == '\r':
                                continue
                            row_1 = item_1.strip()
                            row_1_list = row_1.split()
                            if len(row_1_list) > 3:
                                prev_row = row
                                temp_list = row_1_list[2].split("/")
                            else:
                                next_hop = row_1_list[0]
                                prev_row = ""
                                for d in route_to_dict[destination_address_with_prefix]:
                                    if d.get("next_hop") == next_hop:
                                        d["protocol_attributes"].update(
                                            {"level": temp_list[0]}
                                        )

            # Method for extracting OSPF protocol attributes from router
            def _get_ospf_protocol_attributes(router_name):
                destination_address_with_prefix = ""
                for k, v in route_to_dict.items():
                    destination_address_with_prefix = k
                if destination_address_with_prefix:
                    for d in route_to_dict[destination_address_with_prefix]:
                        d.update({"protocol_attributes": {}})
                    command = f"/show router {router_name} ospf routes {destination_address_with_prefix}"
                    buff_1 = self._perform_cli_commands([command], True, no_more=True)
                    first_row = False
                    for item_1 in buff_1.split("\n"):
                        if destination_address_with_prefix in item_1 or first_row:
                            if "# show" in item_1:
                                continue
                            if not first_row:
                                first_row = True
                                continue
                            row_1 = item_1.strip()
                            row_1_list = row_1.split()
                            next_hop = row_1_list[0]
                            first_row = False
                            for d in route_to_dict[destination_address_with_prefix]:
                                if d.get("next_hop") == next_hop:
                                    d["protocol_attributes"].update({"cost": row_1_list[2]})

            result = to_ele(
                self.conn.get(filter=GET_ROUTE_TO["_"], with_defaults="report-all").data_xml
            )

            name_list = []
            for router in result.xpath(
                "state_ns:state/state_ns:router", namespaces=self.nsmap
            ):
                name_list.append(
                    self._find_txt(router, "state_ns:router-name", namespaces=self.nsmap)
                )
            for vprn in result.xpath(
                "state_ns:state/state_ns:service/state_ns:vprn", namespaces=self.nsmap
            ):
                name_list.append(
                    self._find_txt(vprn, "state_ns:oper-service-id", namespaces=self.nsmap)
                )

            for name in name_list:

                bgp_once = False
                isis_once = False
                local_once = False
                ospf_once = False
                static_once = False

                if longer:
                    if "/" not in destination:
                        destination_address_with_prefix = destination + "/32"
                    else:
                        destination_address_with_prefix = destination
                    cmd = f"/show router {name} route-table {destination_address_with_prefix} longer\n"
                else:
                    cmd = f"/show router {name} route-table {destination} \n"

                buff = self._perform_cli_commands([cmd], True, no_more=True)
                for item in buff.split("\n"):
                    if self.ipv4_address_re.search(item):
                        if "# show" in item:
                            continue
                        row = item.strip()
                        row_list = row.split()
                        if len(row_list) > 2:
                            local_protocol = row_list[2].lower()
                            if local_protocol == "bgp":
                                if not bgp_once:
                                    _get_protocol_attributes(name, local_protocol)
                                    bgp_once = True
                                    _get_bgp_protocol_attributes(name)
                            if local_protocol == "isis":
                                if not isis_once:
                                    _get_protocol_attributes(name, local_protocol)
                                    isis_once = True
                                    _get_isis_protocol_attributes(name)
                            elif local_protocol == "local":
                                if not local_once:
                                    _get_protocol_attributes(name, local_protocol)
                                    local_once = True
                            elif local_protocol == "ospf":
                                if not ospf_once:
                                    _get_protocol_attributes(name, local_protocol)
                                    ospf_once = True
                                    _get_ospf_protocol_attributes(name)
                            elif local_protocol == "static":
                                if not static_once:
                                    _get_protocol_attributes(name, local_protocol)
                                    static_once = True
            return route_to_dict
        except Exception as e:
            print("Error in method get route to : {}".format(e))
            log.error("Error in method get route to : %s" % traceback.format_exc())




def hex_to_colon_separated(value):
    # If input is a string, convert to int
    if isinstance(value, str):
        value = int(value, 16)
    # Convert to hex string without "0x", zero-pad to 20 hex digits (10 bytes)
    hex_str = hex(value)[2:].zfill(20)
    # Group into byte pairs and join with colons
    return ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
