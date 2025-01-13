from napalm_sros.sros import NokiaSROSDriver
class CustomSROSDriver(NokiaSROSDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)
