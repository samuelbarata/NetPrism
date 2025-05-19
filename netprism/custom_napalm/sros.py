from napalm_sros.sros import NokiaSROSDriver
import napalm.base.constants as C
from napalm.base.helpers import convert
import traceback
import logging
from lark import Lark, Transformer, v_args

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
    def lost_ping(self, star_token):
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
        super().__init__(hostname, username, password, timeout, optional_args)

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
