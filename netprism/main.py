from importlib.metadata import PackageNotFoundError
from typing import Any, Dict, List, Optional, Callable
import importlib
from fnmatch import fnmatch
import sys
import os
import tempfile
from datetime import timedelta
from copy import deepcopy

from ruamel.yaml import YAML

from nornir import InitNornir
from nornir.core import Nornir

from nornir.core.task import Result, Task, AggregatedResult, MultiResult
from nornir_napalm.plugins.tasks import napalm_get, napalm_cli, napalm_configure, napalm_ping

from nornir.core.inventory import Host

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.box import MINIMAL_DOUBLE_HEAD
from rich.style import Style
from rich.theme import Theme

from nornir_utils.plugins.functions import print_result

import click
from click.core import Context
from jinja2 import Environment, TemplateNotFound, select_autoescape, FileSystemLoader


PYTHON_PKG_NAME = "netprism"

DEFAULTS = {
    "srl": {
        'username': 'admin',
        'password': 'NokiaSrl1!',
        'gnmi_port': 57400,
        'jsonrpc_port': 80,
        'insecure': True, # Allow jasonrpc 80 instead of 443
    },
    "junos": {
        'username': 'admin',
        'password': 'admin@123',
    },
    "sros": {
        'username': 'admin',
        'password': 'admin',
    }
}


NORNIR_DEFAULT_CONFIG: Dict[str, Any] = {
    "inventory": {
        "plugin": "YAMLInventory",
        "options": {
            "host_file": "clab_hosts.yml",
            "group_file": "clab_groups.yml",
            "defaults_file": "clab_defaults.yml",
        },
    },
    "runner": {
        "plugin": "threaded",
        "options": {
            "num_workers": 20,
        },
    },
    "user_defined": {
        "intent_dir": "intent",
    },
}

SHOW_RESULT_ON_CONFIGURE = True


# Compute path to the templates folder next to this file
BASE_DIR = os.path.dirname(__file__)
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# Prepare Jinja2 environment
jEnv = Environment(
    loader=FileSystemLoader(
        searchpath=TEMPLATE_DIR,
        followlinks=True,
        encoding="utf-8"
    ),
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=select_autoescape(),
)


def get_project_version():
    try:
        version = importlib.metadata.version(PYTHON_PKG_NAME)
    except PackageNotFoundError:
        version = "Version not found"

    return version

def print_table(
    title: str,
    resource: str,
    headers: List[dict],
    results: Dict[str, List],
    filter: Optional[Dict],
    **kwargs,
) -> None:
    table_theme = Theme(
        {
            "ok": "green",
            "warn": "orange3",
            "info": "blue",
            "err": "bold red",
        }
    )
    STYLE_MAP = {
        "up": "[ok]",
        "down": "[err]",
        "enable": "[ok]",
        "disable": "[info]",
        "routed": "[cyan]",
        "bridged": "[blue]",
        "established": "[ok]",
        "active": "[cyan]",
        "connect": "[warn]",
    }


    console = Console(theme=table_theme)
    console._emoji = False
    if kwargs.get("box_type") and kwargs["box_type"] != None:
        box_type = str(kwargs["box_type"]).upper()
        try:
            box_t = getattr(importlib.import_module("rich.box"), box_type)
        except AttributeError:
            print(
                f"Unknown box type {box_type}. Check 'python -m rich.box' for valid box types."
            )
            box_t = MINIMAL_DOUBLE_HEAD
    else:
        box_t = MINIMAL_DOUBLE_HEAD
    #    table = Table(title=title, highlight=True, box=MINIMAL_DOUBLE_HEAD)
    table = Table(title=title, highlight=True, box=box_t)
    col_names=[]
    table.add_column("Node", no_wrap=True)
    for entry in headers:
        for value in entry.values():
            col_names.append(value)
            table.add_column(value, no_wrap=False)

    def pass_filter(row: dict, filter: Optional[Dict]) -> bool:
        if filter is None:
            return True
        filter = {str(k).lower(): v for k, v in filter.items()}
        matched = {
            k: v
            for k, v in row.items()
            if filter.get(str(k).lower()) and fnmatch(str(row[k]), str(filter[str(k).lower()]))
        }
        return len(matched) >= len(filter)

    for host, host_result in results.items():
        rows = []

        for record in host_result:
            common = {
                key: value
                for key, value in record.items()
                if isinstance(value, (str, int, float))
                or (
                    isinstance(value, list)
                    and len(value) > 0
                    and not isinstance(value[0], dict)
                )
            }

            if pass_filter(common, filter):
                row = {}
                for header in headers:
                    _, value = list(header.items())[0]
                    row[value] = record.get(value, "-")
                rows.append(row)

        first_row = True
        for row in rows:
            styled_row = {
                k: f"{STYLE_MAP.get(str(v).lower(), '')}{v}" for k, v in row.items()
            }
            values = [styled_row.get(k, "") for k in col_names]

            if first_row:
                table.add_row(host, *values)
                first_row = False
            else:
                table.add_row("", *values)

        table.add_section()

    if len(table.rows) > 1:
        console.print(table)
    else:
        console.print("[i]No data...[/i]")

@click.group()
@click.option(
    "--cfg",
    "-c",
    default="nornir_config.yaml",
    show_default=True,
    type=click.Path(),
    help="Nornir config file. Mutually exclusive with -t",
)
@click.option(
    "--inv-filter",
    "-i",
    multiple=True,
    help="inventory filter, e.g. -i site=lab -i role=leaf. Possible filter-fields are defined in inventory. Multiple filters are ANDed",
)
# @click.option(
#    "--format",
#    "-f",
#    multiple=False,
#    type=click.Choice(["table", "json", "yaml"]),
#    default="table",
#    help="Output format",
# )
@click.option(
    "--box-type",
    "-b",
    multiple=False,
    help="box type of printed table, e.g. -b minimal_double_head. 'python -m rich.box' for options",
)
@click.option(
    "--topo-file",
    "-t",
    multiple=False,
    type=click.Path(exists=True),
    help="CLAB topology file, e.g. -t topo.yaml. Mutually exclusive with -c",
)
@click.option(
    "--cert-file",
    multiple=False,
    type=click.Path(exists=True),
    help="CLAB certificate file, e.g. -c ca-root.pem",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode."
)

@click.pass_context
@click.version_option(version=get_project_version())
def cli(
    ctx: Context,
    cfg: str,
    # format: Optional[str] = "table",
    inv_filter: Optional[List] = None,
    #    field_filter: Optional[List] = None,
    box_type: Optional[str] = None,
    topo_file: Optional[str] = None,
    cert_file: Optional[str] = None,
    debug: Optional[bool] = False
) -> None:
    ctx.ensure_object(dict)
    if topo_file:  # CLAB mode, -c ignored, inventory generated from topo file
        yaml = YAML(typ="safe")
        try:
            with open(topo_file, "r") as f:
                topo = yaml.load(f)
        except Exception as e:
            print(f"Failed to load topology file {topo_file}: {e}")
            sys.exit(1)
        lab_name = topo["name"]
        if "prefix" not in topo:
            prefix = f"clab-{lab_name}-"
        else:
            if topo["prefix"] == "__lab-name":
                prefix = f"{lab_name}-"
            elif topo["prefix"] == "":
                prefix = ""
            else:
                prefix = f"{topo['prefix']}-{lab_name}-"
        hosts: Dict[str, Dict[str, Any]] = {}
        def_kind = topo["topology"].get("defaults", {}).get("kind")
        def_image = (
            topo["topology"].get("defaults", {}).get("image")
            or topo["topology"]["kinds"].get(def_kind, {}).get("image")
            if def_kind
            else None
        )
        srlinux_def = True if def_image and "srlinux" in def_image else False
        srl_kinds = [
            k
            for k, v in topo["topology"].get("kinds", {}).items()
            if "/srlinux" in v.get("image")
        ]
        junos_kinds = [
            k
            for k, v in topo["topology"].get("kinds", {}).items()
            if "/juniper" in v.get("image")
        ]
        sros_kinds = [
            k
            for k, v in topo["topology"].get("kinds", {}).items()
            if "sros" in v.get("image")
        ]
        clab_nodes: Dict[str, Dict] = topo["topology"]["nodes"]
        for node, node_spec in clab_nodes.items():
            if (not "kind" in node_spec and srlinux_def) or node_spec.get(
                "kind"
            ) in srl_kinds:
                hosts[f"{prefix}{node}"] = {
                    "hostname": f"{prefix}{node}",
                    "platform": "srlinux",
                    "groups": ["srl"],
                    "data": node_spec.get("labels", {}),
                }
            elif  node_spec.get("kind") in junos_kinds:
                hosts[f"{prefix}{node}"] = {
                    "hostname": f"{prefix}{node}",
                    "platform": "junos",
                    "groups": ["junos"],
                    "data": node_spec.get("labels", {}),
                }
            elif  node_spec.get("kind") in sros_kinds:
                hosts[f"{prefix}{node}"] = {
                    "hostname": f"{prefix}{node}",
                    "platform": "sros",
                    "groups": ["sros"],
                    "data": node_spec.get("labels", {}),
                }
        groups: Dict[str, Dict[str, Any]] = {
            "srl": {
                "connection_options": {
                    "napalm": {
                        "username": DEFAULTS['srl']['username'],
                        "password": DEFAULTS['srl']['password'],
                        "port": DEFAULTS['srl']['gnmi_port'],
                        "extras": {
                            "optional_args":{
                                "gnmi_port": DEFAULTS['srl']['gnmi_port'],
                                "jsonrpc_port": DEFAULTS['srl']['jsonrpc_port'],
                                "insecure": DEFAULTS['srl']['insecure']
                            }
                        },
                    },
                }
            },
            "junos": {
                "connection_options": {
                    "napalm": {
                        "username": DEFAULTS['junos']['username'],
                        "password": DEFAULTS['junos']['password'],
                        "extras": {}
                    },
                }
            },
            "sros": {
                "connection_options": {
                    "napalm": {
                        "username": DEFAULTS['sros']['username'],
                        "password": DEFAULTS['sros']['password'],
                        "extras": {}
                    },
                }
            },
        }
        if cert_file:
            groups["srl"]["connection_options"]["napalm"]["extras"]["optional_args"]["tls_ca"] = cert_file
        if debug:
            NORNIR_DEFAULT_CONFIG.update({"runner": {"plugin": "serial"}})
        try:
            with tempfile.NamedTemporaryFile("w+") as hosts_f:
                yaml.dump(hosts, hosts_f)
                hosts_f.seek(0)
                with tempfile.NamedTemporaryFile("w+") as groups_f:
                    yaml.dump(groups, groups_f)
                    groups_f.seek(0)
                    conf: Dict[str, Any] = NORNIR_DEFAULT_CONFIG
                    conf.update(
                        {
                            "inventory": {
                                "options": {
                                    "host_file": hosts_f.name,
                                    "group_file": groups_f.name,
                                }
                            }
                        }
                    )
                    fabric = InitNornir(**conf)
        except Exception as e:
            raise e
    else:
        fabric = InitNornir(config_file=cfg)

    i_filter = (
        {k: v for k, v in [f.split("=") for f in inv_filter]} if inv_filter else {}
    )
    target: Nornir
    if i_filter:
        target = fabric.filter(**i_filter)
    else:
        target = fabric
    ctx.obj["target"] = target
    ctx.obj["i_filter"] = i_filter

    if box_type:
        box_type = box_type.upper()
    ctx.obj["box_type"] = box_type
    # ctx.obj["format"] = format
    ctx.obj["debug"]=debug


def print_report(
    processed_result: Dict[str, List],
    result: AggregatedResult,
    name: str,
    headers: List[dict],
    box_type: Optional[str] = None,
    f_filter: Optional[Dict] = None,
    i_filter: Optional[Dict] = None,
) -> None:
    title = "[bold]" + name + "[/bold]"
    if f_filter:
        title += "\nFields filter:" + str(f_filter)
    if i_filter:
        title += "\nInventory filter:" + str(i_filter)
    if len(result.failed_hosts) > 0:
        title += "\n[red]Failed hosts:" + str(result.failed_hosts)

    print_table(
        title=title,
        resource=result.name,
        headers=headers,
        results=processed_result,
        filter=f_filter,
        box_type=box_type,
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f state=up -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def sys_info(ctx: Context, field_filter: Optional[List] = None):
    """Displays System Info of nodes"""

    GET = 'facts'
    HEADERS = [{'vendor':'Vendor'}, {'model':'Model'}, {'serial_number':'Serial Number'}, {'os_version':'Software Version'}, {'uptime':'Uptime'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _sys_info(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_sys_info, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult):
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            dev_result = res[node].result[GET]
            if dev_result is None:
                continue
            if isinstance(dev_result['uptime'], float):
                dev_result['uptime'] = str(timedelta(seconds=dev_result['uptime'])) + 's'
            new_res = {}
            for key in dev_result:
                if key in EXISTING_HEADERS:
                    new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
            node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        name="System Info",
        headers=HEADERS,
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f state=up -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def lldp(ctx: Context, field_filter: Optional[List] = None):
    """Displays LLDP Neighbors"""

    GET = 'lldp_neighbors_detail'
    HEADERS = [{'_default': 'Interface'}, {'remote_system_name':'Nbr-System'}, {'remote_port':'Nbr-port'}, {'remote_port_description':'Nbr-port-desc'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _lldp_neighbors(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_lldp_neighbors, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for k in res[node].result[GET]:
                dev_result = res[node].result[GET][k]
                new_res = {HEADERS[0]['_default']: k}
                for obj in dev_result:
                    for key in obj:
                        if key in EXISTING_HEADERS:
                            new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: obj[key]})
                node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        name="LLDP Neighbors",
        headers=HEADERS,
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def arp(ctx: Context, field_filter: Optional[List] = None):
    """Displays ARP table"""

    GET = 'arp_table'
    HEADERS = [{'interface': 'Interface'}, {'mac':'MAC Address'}, {'ip':'IPv4'}, {'Type':'Type'}, {'age':'Expiry'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _arp(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_arp, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for dev_result in res[node].result[GET]:
                if isinstance(dev_result['age'], float):
                    dev_result['Type'] = 'dynamic'
                    dev_result['age'] = str(timedelta(seconds=dev_result['age'])) + 's'
                else:
                    dev_result['Type'] = 'static'
                new_res = {}
                for key in dev_result:
                    if key in EXISTING_HEADERS:
                        new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
                node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="ARP table",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def mac(ctx: Context, field_filter: Optional[List] = None):
    """Displays MAC table"""

    GET = 'get_mac_address_table'
    HEADERS = [{'mac':'MAC Address'}, {'interface':'Destination'}, {'vlan':'Vlan'}, {'static':'Static'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _mac(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_mac, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for dev_result in res[node].result[GET]:
                new_res = {}
                for key in dev_result:
                    if key in EXISTING_HEADERS:
                        new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
                node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="MAC table",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )


@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def bgp_peers(ctx: Context, field_filter: Optional[List] = None):
    """Displays BGP Peers and their status"""
    # FIXME: SROS neighbors AS not working properly

    HEADERS = [{'_default':'VRF'}, {'remote_address':'Peer'}, {'evpn':'EVPN\nRx/Act/Tx'}, {'ipv4':'IPv4\nRx/Act/Tx'}, {'ipv6':'IPv6\nRx/Act/Tx'}, {'export_policy':'Export Policy'}, {'routing_table':'Group'}, {'import_policy':'Import Policy'}, {'local_as':'Local AS'}, {'remote_as':'Remote AS'}, {'connection_state':'State'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _bgp_peers(task: Task) -> Result:
        return napalm_get(task=task, getters=['get_bgp_neighbors', 'get_bgp_neighbors_detail'])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_bgp_peers, name='bgp_peers', raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for vrf in res[node].result['get_bgp_neighbors']:
                for peer in res[node].result['get_bgp_neighbors'][vrf]['peers']:
                    dev_result = res[node].result['get_bgp_neighbors'][vrf]['peers'][peer]
                    dev_result['remote_address'] = peer
                    new_res = {HEADERS[0]['_default']: vrf, 'router_id': res[node].result['get_bgp_neighbors'][vrf]['router_id']}
                    address_family = dev_result['address_family']
                    if 'evpn' in address_family:
                        new_res.update({HEADERS[EXISTING_HEADERS.index('evpn')]['evpn']: f"{address_family['evpn']['received_prefixes']}/{address_family['evpn']['accepted_prefixes']}/{address_family['evpn']['sent_prefixes']}"})
                    if 'ipv6' in address_family:
                       new_res.update({HEADERS[EXISTING_HEADERS.index('ipv6')]['ipv6']: f"{address_family['ipv6']['received_prefixes']}/{address_family['ipv6']['accepted_prefixes']}/{address_family['ipv6']['sent_prefixes']}"})
                    if 'ipv4' in address_family:
                        new_res.update({HEADERS[EXISTING_HEADERS.index('ipv4')]['ipv4']: f"{address_family['ipv4']['received_prefixes']}/{address_family['ipv4']['accepted_prefixes']}/{address_family['ipv4']['sent_prefixes']}"})

                    for key in dev_result:
                        if key in EXISTING_HEADERS:
                            new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
                    node_ret.append(new_res)


            for k in res[node].result['get_bgp_neighbors_detail']:
                dev_result = res[node].result['get_bgp_neighbors_detail'][k]
                for peer_as in dev_result:
                    for connection in dev_result[peer_as]:
                        new_res = list(filter(lambda x: x['Peer'] == connection['remote_address'], node_ret))[0]

                        for key in connection:
                            if key in EXISTING_HEADERS:
                                new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: connection[key]})

                        if new_res[HEADERS[EXISTING_HEADERS.index('remote_as')]['remote_as']] == 0:
                            new_res[HEADERS[EXISTING_HEADERS.index('remote_as')]['remote_as']] = new_res[HEADERS[EXISTING_HEADERS.index('local_as')]['local_as']]


            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="BGP Peers",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )


@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def users(ctx: Context, field_filter: Optional[List] = None):
    """Displays Users table"""

    GET = 'get_users'
    HEADERS = [{'_default':'User'}, {'level':'Level'}, {'password': 'Password'}, {'sshkeys': 'SSH Keys'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _users(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_users, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for k in res[node].result[GET]:
                dev_result = res[node].result[GET][k]
                new_res = {HEADERS[0]['_default']: k}

                for key in dev_result:
                    if key in EXISTING_HEADERS:
                        if key == 'password':
                            new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]!=None and dev_result[key]!=''})
                        else:
                            new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
                node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="Users table",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f state=up -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def ni(ctx: Context, field_filter: Optional[List] = None):
    """Displays Network Instances"""

    GET = ['get_network_instances', 'get_interfaces', 'get_interfaces_ip']
    # HEADERS = {'name': 'Name', 'type':'Type', 'interfaces':'Sub-Interfaces', 'mtu': 'MTU', 'speed':'Speed', 'description':'Description', 'ip_prefix': 'IP Prefix', 'mac_address': 'MAC Address'}
    HEADERS = [{'name': 'Name'}, {'type':'Type'}, {'interfaces':'Sub-Interfaces'}, {'mtu': 'MTU'}, {'speed':'Speed'}, {'description':'Description'}, {'ip_prefix': 'IP Prefix'}, {'mac_address': 'MAC Address'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]
    # EXISTING_HEADERS = list(HEADERS.keys())

    def _ni(task: Task) -> Result:
        return napalm_get(task=task, getters=GET)

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_ni, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for k in res[node].result['get_network_instances']:
                dev_result = res[node].result['get_network_instances'][k]
                new_res = {}
                for key in dev_result:
                    if key in EXISTING_HEADERS:
                        new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})

                new_res['Type'] = new_res['Type'].replace('srl_nokia-network-instance:', '')
                for sub_if in dev_result['interfaces']['interface']:
                    tmp = deepcopy(new_res)
                    tmp['Sub-Interfaces'] = sub_if

                    if sub_if in res[node].result['get_interfaces']:
                        int_restuls = res[node].result['get_interfaces'][sub_if]
                    elif sub_if.split('.')[0] in res[node].result['get_interfaces']:
                        int_restuls = res[node].result['get_interfaces'][sub_if.split('.')[0]]
                    else:
                        int_restuls = {}
                    for int_key in int_restuls:
                        if int_key in EXISTING_HEADERS:
                            if int_key == 'description' and int_restuls[int_key] == '':
                                continue
                            tmp.update({HEADERS[EXISTING_HEADERS.index(int_key)][int_key]: int_restuls[int_key]})
                    if sub_if in res[node].result['get_interfaces_ip']:
                        int_ip = res[node].result['get_interfaces_ip'][sub_if]
                    else:
                        int_ip = {}

                    int_ips = [f"{addr}/{int_ip[family][addr]['prefix_length']}" for family in int_ip for addr in int_ip[family]]
                    if len(int_ips) > 0:
                        tmp[HEADERS[EXISTING_HEADERS.index('ip_prefix')]['ip_prefix']] = int_ips

                    node_ret.append(tmp)

            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        name="Network Instances",
        headers=HEADERS,
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f state=up -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def rib(ctx: Context, field_filter: Optional[List] = None):
    """Displays Routing Table"""
    # FIXME: SROS

    GET = 'get_route_to'
    HEADERS = [{'_default':'Route'}, {'protocol':'Protocol'}, {'next_hop':'Next Hop'}, {'selected_next_hop':'Selected Next Hop'}, {'preference':'preference'}, {'routing_table': 'Routing Table'}, {'outgoing_interface':'Outgoing Interface'}, {'as_path':'AS Path'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _rib(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_rib, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult):
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            if not res[node].result[GET]:
                continue
            for k in res[node].result[GET]:
                if k is None:
                    continue
                dev_result = res[node].result[GET][k]

                for route in dev_result:
                    new_res = {HEADERS[0]['_default']: k}
                    for key in route:
                        if key in EXISTING_HEADERS:
                            if route[key] != '' and route[key] != -1:
                                new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: route[key]})
                        if key == 'protocol_attributes':
                            for proto_arg in route[key]:
                                if proto_arg in EXISTING_HEADERS:
                                    new_res.update({HEADERS[EXISTING_HEADERS.index(proto_arg)][proto_arg]: route[key][proto_arg]})

                    node_ret.append(new_res)


            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        name="RIB",
        headers=HEADERS,
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def vlans(ctx: Context, field_filter: Optional[List] = None):
    """Displays Vlans table"""

    GET = 'get_vlans'
    HEADERS = [{'_default':'VLan ID'}, {'name':'Name'}, {'interfaces': 'Interfaces'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _vlans(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_vlans, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for k in res[node].result[GET]:
                dev_result = res[node].result[GET][k]
                new_res = {HEADERS[0]['_default']: k}

                for key in dev_result:
                    if key in EXISTING_HEADERS:
                        new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
                node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="VLans Table",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )

@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def es(ctx: Context, field_filter: Optional[List] = None):
    """Displays Ethernet Segments"""

    GET = 'get_ethernet_segments'
    HEADERS = [{'name':'Name'}, {'esi':'ESI'}, {'multi-homing-mode': 'MH Mode'}, {'interface': 'Interfaces'}, {'_ni_peers':'NI Peers'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _es(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_es, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for dev_result in res[node].result[GET]:
                new_res = {}

                for key in dev_result:
                    if key == 'interface':
                        new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: [interface[key] for interface in dev_result[key] for key in interface]})
                    elif key == 'association':
                        ni = dev_result[key].get('network-instance', [])
                        _ni_peers = [obj.get('_ni_peers', None) for obj in ni]
                        if len(_ni_peers) == 0:
                            continue
                        elif len(_ni_peers) == 1:
                            _ni_peers = _ni_peers[0]
                        new_res.update({HEADERS[EXISTING_HEADERS.index('_ni_peers')]['_ni_peers']: _ni_peers})

                    elif key in EXISTING_HEADERS:
                        new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
                node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="Ethernet Segments Table",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )


@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
def lag(ctx: Context, field_filter: Optional[List] = None):
    """Displays Link Agregation"""

    GET = 'get_link_agregation_groups'
    HEADERS = [{'name':'LAG'}, {'mtu':'MTU'}, {'min_links': 'min'}, {'lag_type': 'Type'}, {'lag_speed':'Speed'}, {'key': 'LACP Key'}, {'lacp_interval': 'LACP Interval'}, {'lacp_mode': 'LACP Mode'}, {'system_id': 'LACP System ID'}, {'activity': 'LACP Activity'}, {'interface': 'Interface'}, {'synchronization': 'Syncronization'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _lag(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_lag, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult) -> AggregatedResult:
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            for dev_result in res[node].result[GET]:
                tmp_res = {}

                for key in dev_result:
                    if key in EXISTING_HEADERS:
                        tmp_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})

                for member in dev_result['members']:
                    new_res = deepcopy(tmp_res)
                    for k2 in member:
                        if k2 in EXISTING_HEADERS:
                            new_res.update({HEADERS[EXISTING_HEADERS.index(k2)][k2]: member[k2]})
                    node_ret.append(new_res)

            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        headers=HEADERS,
        name="Link Agregation Groups Table",
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )


@cli.command()
@click.pass_context
@click.option(
    "--field-filter",
    "-f",
    multiple=True,
    help='filter fields with <field-name>=<glob-pattern>, e.g. -f name=ge-0/0/0 -f admin_state="ena*". Fieldnames correspond to column names of a report',
)
@click.option(
    "--timeout",
    "-t",
    default=5,
    help="Timeout for the ping",
)
@click.option(
    "--count",
    "-c",
    default=5,
    help="Count for the ping",
)
@click.option(
    "--size",
    "-s",
    default=64,
    help="Size for the ping",
)
@click.option(
    "--source",
    "-S",
    default=None,
    help="Source address for the ping",
)
@click.option(
    "--destination",
    "-D",
    default=None,
    help="Destination address for the ping",
)
@click.option(
    "--vrf",
    "-v",
    default=None,
    help="VRF for the ping",
)
def ping(ctx: Context, destination: str, source: Optional[str] = None, size: Optional[int] = None, count: Optional[int] = None, timeout: Optional[int] = None, vrf: Optional[str] = None, field_filter: Optional[List] = None):
    """Displays PINGS"""

    GET = 'ping'
    HEADERS = [{'rtt_avg':'Average'}, {'rtt_max':'Max'}, {'rtt_min': 'Min'}, {'rtt_stddev': 'StDev'}, {'packet_loss':'packet_loss'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _ping(task: Task) -> Result:
        return napalm_ping(task=task, dest=destination, source=source, size=size, count=count, timeout=timeout, vrf=vrf)

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_ping, name=GET, raise_on_error=False
    )

    if(ctx.obj['debug']):
        print_result(result)

    def _process_results(res: AggregatedResult):
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            if res[node].result is None:
                continue
            if 'error' in res[node].result:
                ret[node] = [{HEADERS[4]['packet_loss']: f"{count}/{count}"}]
                continue
            else:
                dev_result = res[node].result['success']
            if dev_result is None:
                continue
            new_res = {}
            for key in dev_result:
                if key == 'packet_loss':
                    new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: f"{dev_result[key]}/{count}"})
                elif key in EXISTING_HEADERS:
                    new_res.update({HEADERS[EXISTING_HEADERS.index(key)][key]: dev_result[key]})
            node_ret.append(new_res)
            ret[node] = node_ret
        return ret

    processed_result = _process_results(result)

    print_report(
        processed_result=processed_result,
        result=result,
        name=f"Ping {destination}",
        headers=HEADERS,
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )



@cli.group
@click.pass_context
def configure(ctx: Context, devices: Optional[List] = None):
    """Configure nodes"""
    pass

@configure.command()
@click.pass_context
@click.option(
    "--username",
    "-u",
    default=None,
    help="Username for the user to create",
)
@click.option(
    "--password",
    "-p",
    default=None,
    help="Password for the user to create",
)
@click.option(
    "--rsa-key",
    default=None,
    multiple=True,
    help="SSH Key for the user to create",
)
@click.option(
    "--ecdsa-key",
    default=None,
    multiple=True,
    help="SSH Key for the user to create",
)
@click.option(
    "--dry-run",
    is_flag=True,
    type=bool,
    help="Dry run",
)
@click.option(
    "--level",
    "-l",
    default=None,
    help="Level for the user to create (0-15)",
    type=int
)
def user(ctx: Context, username: str, password: Optional[str] = None, rsa_key: Optional[List] = None, ecdsa_key: Optional[List] = None, dry_run: Optional[bool] = False, level: Optional[int] = None):
    """Create new User"""

    user_details = {'username': username}
    if password:
        user_details['password'] = password
    if rsa_key or ecdsa_key:
        user_details['sshkeys'] = []
        if rsa_key:
            user_details['sshkeys'].extend(rsa_key)
        if ecdsa_key:
            user_details['sshkeys'].extend(ecdsa_key)
    if level:
        user_details['level'] = level

    def _user(task: Task) -> Result:
        try:
            template = jEnv.get_template(f"{task.host.platform}/create_user.j2")
        except TemplateNotFound:
            return Result(host=task.host, failed=True, result=f"Template not found for platform {task.host.platform}")
        config = template.render(user_details=user_details)
        return napalm_configure(task=task, dry_run=dry_run, configuration=config)

    result = ctx.obj["target"].run(
        task=_user, name='user', raise_on_error=False
    )

    if(ctx.obj['debug'] or dry_run or SHOW_RESULT_ON_CONFIGURE):
        print_result(result)


@configure.command()
@click.pass_context
@click.option(
    "--dry-run",
    is_flag=True,
    type=bool,
    help="Dry run",
)
@click.option(
    "--vrf",
    default=None,
    type=str,
    help="VRF ID for the VRF to create (e.g. vrf-100)",
)
@click.option(
    "--vxlan-interface",
    default=None,
    type=str,
    help="VxLAN interface for the VRF to create (e.g. vxlan1.2)",
)
@click.option(
    "--bgp-instance",
    default=None,
    type=int,
    help="BGP instance to assign to the evpn",
)
@click.option(
    "--bgp-evi",
    default=None,
    type=int,
    help="BGP EVI to assign to the evpn",
)
@click.option(
    "--bgp-ecmp",
    default=1,
    type=int,
    help="BGP equal-cost multipath (ECMP)"
)
@click.option(
    "--route-target-export",
    default=None,
    type=str,
    help="BGP route-target to export to evpn (e.g. target:100:1)",
)
@click.option(
    "--route-target-import",
    default=None,
    type=str,
    help="BGP route-target to import from evpn (e.g. target:100:1)",
)
def mac_vrf(ctx: Context, vrf: str, vxlan_interface: str, bgp_instance: int, bgp_evi: int, route_target_export: str, route_target_import: str, bgp_ecmp: Optional[int] = 1, dry_run: Optional[bool] = False):
    """Create new MAC VRF"""

    vxlan_interface_split = vxlan_interface.split('.')
    options = {
        'vrf': vrf,
        'vxlan': vxlan_interface_split[0],
        'vxlan_int': vxlan_interface_split[1],
        'vxlan_interface': vxlan_interface,
        'bgp_instance': bgp_instance,
        'evi': bgp_evi,
        'ecmp': bgp_ecmp,
        'export_rt': route_target_export,
        'import_rt': route_target_import
    }

    def _mac_vrf(task: Task) -> Result:
        try:
            template = jEnv.get_template(f"{task.host.platform}/create_mac_vrf.j2")
        except TemplateNotFound:
            return Result(host=task.host, failed=True, result=f"Template not found for platform {task.host.platform}")
        
        config = template.render(options=options)
        return napalm_configure(task=task, dry_run=dry_run, configuration=config)

    result = ctx.obj["target"].run(
        task=_mac_vrf, name='MAC VRF', raise_on_error=False
    )

    if(ctx.obj['debug'] or dry_run or SHOW_RESULT_ON_CONFIGURE):
        print_result(result)

if __name__ == "__main__":
    cli(obj={})
