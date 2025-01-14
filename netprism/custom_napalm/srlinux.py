from napalm_srl.srl import NokiaSRLDriver
class CustomSRLDriver(NokiaSRLDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        opt_args = {
            "gnmi_port": 57400,
            "jsonrpc_port": 443,
            "target_name": hostname,
            "skip_verify": False,
            "insecure": False,
            "encoding": "JSON_IETF"
        }
        opt_args.update(optional_args)

        super().__init__(hostname, username, password, timeout, opt_args)
