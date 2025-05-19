from typing import Optional
from nornir.core.task import Result, Task

from nornir_napalm.plugins.connections import CONNECTION_NAME
import napalm.base.constants as C

def napalm_traceroute(
    task: Task,
    destination: str,
    source: Optional[str] = C.TRACEROUTE_SOURCE,
    ttl: Optional[int] = C.TRACEROUTE_TTL,
    timeout: Optional[int] = C.TRACEROUTE_TIMEOUT,
    vrf: Optional[str] = C.TRACEROUTE_VRF,
) -> Result:
    """
    Executes traceroute on the device and returns a dictionary with the result.

    :param destination: Host or IP Address of the destination
    :param source: Use a specific IP Address to execute the traceroute
    :type source: optional
    :param ttl: Maximum number of hops
    :type ttl: optional
    :param timeout: Number of seconds to wait for response
    :type timeout: optional
    :param vrf: Use a specific VRF to execute the traceroute
    :type vrf: optional

    Output dictionary has one of the following keys:

        * success
        * error

    In case of success, the keys of the dictionary represent the hop ID, while values are
    dictionaries containing the probes results:

        * rtt (float)
        * ip_address (str)
        * host_name (str)

    Example::

        {
            'success': {
                1: {
                    'probes': {
                        1: {
                            'rtt': 1.123,
                            'ip_address': u'206.223.116.21',
                            'host_name': u'eqixsj-google-gige.google.com'
                        },
                        2: {
                            'rtt': 1.9100000000000001,
                            'ip_address': u'206.223.116.21',
                            'host_name': u'eqixsj-google-gige.google.com'
                        },
                        3: {
                            'rtt': 3.347,
                            'ip_address': u'198.32.176.31',
                            'host_name': u'core2-1-1-0.pao.net.google.com'}
                        }
                    },
                    2: {
                        'probes': {
                            1: {
                                'rtt': 1.586,
                                'ip_address': u'209.85.241.171',
                                'host_name': u'209.85.241.171'
                                },
                            2: {
                                'rtt': 1.6300000000000001,
                                'ip_address': u'209.85.241.171',
                                'host_name': u'209.85.241.171'
                            },
                            3: {
                                'rtt': 1.6480000000000001,
                                'ip_address': u'209.85.241.171',
                                'host_name': u'209.85.241.171'}
                            }
                        },
                    3: {
                        'probes': {
                            1: {
                                'rtt': 2.529,
                                'ip_address': u'216.239.49.123',
                                'host_name': u'216.239.49.123'},
                            2: {
                                'rtt': 2.474,
                                'ip_address': u'209.85.255.255',
                                'host_name': u'209.85.255.255'
                            },
                            3: {
                                'rtt': 7.813,
                                'ip_address': u'216.239.58.193',
                                'host_name': u'216.239.58.193'}
                            }
                        },
                    4: {
                        'probes': {
                            1: {
                                'rtt': 1.361,
                                'ip_address': u'8.8.8.8',
                                'host_name': u'google-public-dns-a.google.com'
                            },
                            2: {
                                'rtt': 1.605,
                                'ip_address': u'8.8.8.8',
                                'host_name': u'google-public-dns-a.google.com'
                            },
                            3: {
                                'rtt': 0.989,
                                'ip_address': u'8.8.8.8',
                                'host_name': u'google-public-dns-a.google.com'}
                            }
                        }
                    }
                }

        OR

        {
            'error': 'unknown host 8.8.8.8'
        }
    """
    device = task.host.get_connection(CONNECTION_NAME, task.nornir.config)
    result = device.traceroute(
        destination = destination,
        source = source,
        ttl = ttl,
        timeout = timeout,
        vrf = vrf,
    )
    return Result(host=task.host, result=result)
