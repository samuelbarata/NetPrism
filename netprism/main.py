from importlib.metadata import PackageNotFoundError
from typing import Any, Dict, List, Optional, Callable
import importlib
import fnmatch
import sys
import tempfile
from datetime import timedelta

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


PYTHON_PKG_NAME = "netprism"

DEFAULTS = {
    "srl": {
        'username': 'admin',
        'password': 'NokiaSrl1!',
        'gnmi_port': 57400,
    },
    "junos": {
        'username': 'admin',
        'password': 'admin@123',
    },
    "sros": {
        'username': 'admin',
        'password': 'admin2',
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
    # "runner": {
    #     "plugin": "serial",
    # },
    "user_defined": {
        "intent_dir": "intent",
    },
}

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
                k: f"{STYLE_MAP.get(str(v), '')}{v}" for k, v in row.items()
            }
            values = [styled_row.get(k, "") for k in col_names]

            if first_row:
                table.add_row(host, *values)
                first_row = False
            else:
                table.add_row("", *values)

        table.add_section()

    if len(table.columns) > 1:
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
@click.pass_context
@click.version_option(version=get_project_version())
def cli(
    ctx: Context,
    cfg: str,
    format: Optional[str] = None,
    inv_filter: Optional[List] = None,
    #    field_filter: Optional[List] = None,
    box_type: Optional[str] = None,
    topo_file: Optional[str] = None,
    cert_file: Optional[str] = None,
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
            if "/sros" in v.get("image")
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
                "username": DEFAULTS['srl']['username'],
                "password": DEFAULTS['srl']['password'],
                "port": DEFAULTS['srl']['gnmi_port'],
                "extras": {},
                "connection_options": {
                    "srlinux": {
                        "username": DEFAULTS['srl']['username'],
                        "password": DEFAULTS['srl']['password'],
                        "port": DEFAULTS['srl']['gnmi_port'],
                        "extras": {},
                    },
                }
            },
            "junos": {
                "username": DEFAULTS['junos']['username'],
                "password": DEFAULTS['junos']['password'],
                "connection_options": {
                    "junos": {
                        "username": DEFAULTS['junos']['username'],
                        "password": DEFAULTS['junos']['password'],
                    },
                }
            },
            "sros": {
                "username": DEFAULTS['sros']['username'],
                "password": DEFAULTS['sros']['password'],
                "connection_options": {
                    "sros": {
                        "username": DEFAULTS['sros']['username'],
                        "password": DEFAULTS['sros']['password'],
                    },
                }
            },
        }
        if cert_file:
            groups["srl"]["connection_options"]["srlinux"]["extras"][
                "path_cert"
            ] = cert_file

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
    ctx.obj["format"] = format


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
    HEADERS = [{'vendor':'vendor'}, {'model':'model'}, {'serial_number':'serial-number'}, {'os_version':'software-version'}, {'uptime':'uptime'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _sys_info(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_sys_info, name=GET, raise_on_error=False
    )

    print_result(result)

    def _process_results(res: AggregatedResult):
        ret = {}
        for node in res:
            if res[node].failed:
                continue
            node_ret = []
            dev_result = res[node].result[GET]
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
    HEADERS = [{'interface': 'interface'}, {'mac':'MAC'}, {'ip':'IPv4'}, {'Type':'Type'}, {'age':'expiry'}, {'vrf':'vrf'}]
    EXISTING_HEADERS = [list(obj.keys())[0] for obj in HEADERS]

    def _arp(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )

    result = ctx.obj["target"].run(
        task=_arp, name=GET, raise_on_error=False
    )

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


if __name__ == "__main__":
    cli(obj={})
