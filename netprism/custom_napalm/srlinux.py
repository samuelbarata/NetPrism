from napalm_srl.srl import NokiaSRLDriver
class CustomSRLDriver(NokiaSRLDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        optional_args = {
            "gnmi_port": 57400,
            "jsonrpc_port": 80,
            "target_name": "sr1",
            "tls_cert":"/home/samuelbarata/labs/dsi-dc2/clab-dsi/.tls/sr1/sr1.pem",
            "tls_ca": "/home/samuelbarata/labs/dsi-dc2/clab-dsi/.tls/ca/ca.pem",
            "tls_key": "/home/samuelbarata/labs/dsi-dc2/clab-dsi/.tls/sr1/sr1.key",
            "skip_verify": True,
            "insecure": True,
            "encoding": "JSON_IETF"
        }
        super().__init__(hostname, username, password, timeout, optional_args)
