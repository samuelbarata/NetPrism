from importlib.metadata import PackageNotFoundError
from typing import Any, Dict, List, Optional, Callable
import importlib
import fnmatch
import sys
import tempfile

from ruamel.yaml import YAML

from nornir import InitNornir
from nornir.core import Nornir

from nornir.core.task import Result, Task, AggregatedResult
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
    # "runner": {
    #     "plugin": "threaded",
    #     "options": {
    #         "num_workers": 20,
    #     },
    # },
    "runner": {
        "plugin": "serial",
    },
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
    results: AggregatedResult,
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
        r: Result = host_result[0]
        node: Host = r.host if r.host else Host("unkown")
        if r.failed:
            print(f"Failed to get {resource} for {host}. Exception: {r.exception}")
            continue

        data = r.result.get(resource, {})
        rows = []

        print(r.result.get(resource, {}))
        # {'hostname': 'sr1', 'fqdn': 'sr1', 'vendor': 'Nokia', 'model': '7220 IXR-D2L'}
        # {'ethernet-1/1': [{'parent_interface': 'ethernet-1/1', 'remote_port': '520', 'remote_port_description': 'ge-0/0/0', 'remote_chassis_id': '2C:6B:F5:F6:8A:C0', 'remote_system_name': 'vmx', 'remote_system_description': 'Juniper Networks, Inc. ex9214 Ethernet Switch, kernel JUNOS 23.2R1.14, Build date: 2023-06-22 13:29:14 UTC Copyright (c) 1996-2023 Juniper Networks, Inc.', 'remote_system_capab': ['srl_nokia-lldp-types:MAC_BRIDGE', 'srl_nokia-lldp-types:ROUTER'], 'remote_system_enable_capab': ['srl_nokia-lldp-types:MAC_BRIDGE', 'srl_nokia-lldp-types:ROUTER']}]}
        for k, records in data.items():
            print(k, records)

            for record in records:
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
                        key, value = list(header.items())[0]
                        row[value] = record.get(key, "-") if key != "_default" else k
                    rows.append(row)



        first_row = True
        for row in rows:
            styled_row = {
                k: f"{STYLE_MAP.get(str(v), '')}{v}" for k, v in row.items()
            }
            values = [styled_row.get(k, "") for k in col_names]

            if first_row:
                node_name = node.hostname if hasattr(node, 'hostname') and node.hostname else node.name
                table.add_row(node_name, *values)
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
    result: AggregatedResult,
    name: str,
    failed_hosts: List,
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
    if len(failed_hosts) > 0:
        title += "\n[red]Failed hosts:" + str(failed_hosts)

    print_table(
        title=title,
        resource=result.name,
        headers=headers,
        results=result,
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
    HEADERS = [{'vendor':'vendor'}, {'type':'model'}, {'serial_number':'serial-number'}, {'os_version':'software-version'}]

    def _sys_info(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_sys_info, name=GET, raise_on_error=False
    )

    print_result(result)

    print_report(
        result=result,
        name="System Info",
        headers=HEADERS,
        failed_hosts=result.failed_hosts,
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

    def _lldp_neighbors(task: Task) -> Result:
        return napalm_get(task=task, getters=[GET])

    f_filter = (
        {k: v for k, v in [f.split("=") for f in field_filter]} if field_filter else {}
    )
    result = ctx.obj["target"].run(
        task=_lldp_neighbors, name=GET, raise_on_error=False
    )

    print_result(result)

    print_report(
        result=result,
        name="LLDP Neighbors",
        headers=HEADERS,
        failed_hosts=result.failed_hosts,
        box_type=ctx.obj["box_type"],
        f_filter=f_filter,
        i_filter=ctx.obj["i_filter"],
    )



if __name__ == "__main__":
    cli(obj={})
