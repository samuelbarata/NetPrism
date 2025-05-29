from napalm_sros.sros import NokiaSROSDriver
import napalm.base.constants as C
from napalm.base.helpers import convert
import traceback
import logging
from lark import Lark, Transformer, v_args
from pygnmi.client import gNMIclient

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

        self.gnmi = None
        self.gnmi_host = optional_args.get("gnmi_host", hostname)
        self.gnmi_port = optional_args.get("gnmi_port", 57400)
        self.gnmi_tls = optional_args.get("gnmi_tls", opt_args['insecure'])

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
        raise NotImplementedError

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
