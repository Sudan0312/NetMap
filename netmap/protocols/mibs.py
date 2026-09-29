"""MIB object registry used by NetMap's SNMP enumeration.

Grouped by the enumeration task that consumes them so a new data source is a
one-line addition here plus a handler in ``discovery/snmp_enum.py``.
"""

from __future__ import annotations

# RFC 1213 system group
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

SYSTEM_BASE = "1.3.6.1.2.1.1"

# RFC 2863 interfaces group
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_MTU = "1.3.6.1.2.1.2.2.1.4"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"

# RFC 4293 / 2011 ip: the ARP table is the bridge between L3 and L2
IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22.1"
IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"
IP_NET_TO_MEDIA_IP = "1.3.6.1.2.1.4.22.1.3"
IP_NET_TO_MEDIA_IF = "1.3.6.1.2.1.4.22.1.4"
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.5"
IP_ADENT_IF = "1.3.6.1.2.1.4.20.1.1"
IP_ADENT_LOCAL = "1.3.6.1.2.1.4.20.1.2"
IP_ADENT_BCAST = "1.3.6.1.2.1.4.20.1.3"
IP_ROUTE_DEST = "1.3.6.1.2.1.4.21.1.1"
IP_ROUTE_NEXT_HOP = "1.3.6.1.2.1.4.21.1.7"
IP_ROUTE_IF = "1.3.6.1.2.1.4.21.1.3"
IP_ROUTE_TYPE = "1.3.6.1.2.1.4.21.1.4"
IP_ROUTE_PROTO = "1.3.6.1.2.1.4.21.1.6"

# RFC 1493 bridge MIB: MAC address table -> switch port -> attached host
DOT1D_BASE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.1.2"
DOT1D_BASE_PORT_NUM = "1.3.6.1.2.1.17.1.4.1.1.1"
DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_TP_FDB_AGE = "1.3.6.1.2.1.17.4.3.1.3"
DOT1Q_VLAN_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"

# LLDP-MIB (IEEE 802.1AB)
LLDP_LOC_SYS_NAME = "1.0.8802.1.1.2.1.3.2.0"
LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.6"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_DESC = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"

# CISCO-CDP-MIB
CDP_CACHE_ENTRY = "1.3.6.1.4.1.9.9.23.1.2.1"
CDP_CACHE_IFACE = "1.3.6.1.4.1.9.9.23.1.2.1.1.1"
CDP_CACHE_ADDR = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_CACHE_DEV_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEV_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_CAP = "1.3.6.1.4.1.9.9.23.1.2.1.1.5"
CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
CDP_CACHE_VERSION = "1.3.6.1.4.1.9.9.23.1.2.1.1.9"

# CISCO-PROCESS-MIB / -ENV-MON: health signals used by risk scoring
CISCO_CPU_LOAD = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"
ENV_TEMPERATURE = "1.3.6.1.4.1.9.9.13.1.3.1.3.1"
CISCO_IMAGE = "1.3.6.1.4.1.9.9.109.1.3.1.1.1.2"

# HOST-RESOURCES-MIB (servers)
HR_SYSTEM_DESC = "1.3.6.1.2.1.25.4.0"
HR_SW_NAME = "1.3.6.1.2.1.25.4.2.1.2"
HR_SW_PATH = "1.3.6.1.2.1.25.4.2.1.4"
HR_SW_TYPE = "1.3.6.1.2.1.25.4.2.1.5"
HR_FS_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_DEVICE_STATUS = "1.3.6.1.2.1.25.3.2.1.5"
HR_DEVICE_UP = "1.3.6.1.2.1.25.3.2.1.11"

# Net-SNMP extensions commonly used for host hardening telemetry
NETSNMP_OS = {
    "hrd_os_version": "1.3.6.1.4.1.2021.4.5.0",
    "hrd_os_release": "1.3.6.1.4.1.2021.4.6.0",
    "hrd_procs_running": "1.3.6.1.4.1.2021.4.14.0",
    "hrd_load_1m": "1.3.6.1.4.1.2021.10.3.3.1.3",
    "mntpoint": "1.3.6.1.4.1.2021.9.1.2",
    "dskpercent": "1.3.6.1.4.1.2021.9.1.10",
    "snmpd_listen": "1.3.6.1.4.1.2021.1.1.0",  # snmpd config: local ports/addresses
}

# sysObjectID enterprise → vendor (subset commonly seen in enterprises)
ENTERPRISE_VENDORS = {
    "9": "cisco",
    "2636": "huawei",
    "11": "hpe",
    "2011": "hewlett-packard-enterprise",
    "476": "aruaba",
    "1991": "juniper",
    "25461": "palo-alto",
    "12356": "fortinet",
    "3031": "arista",
    "19155": "palo-alto-alt",
    "2636.55": "huawei",
    "171": "broadcom",
    "1916": "dell",
    "674": "lenovo",
    "8072": "netapp",
    "2021": "net-snmp",
    "232": "redhat",
    "1482": "f5",
    "3902": "citrix",
    "6876": "vmware",
    "25506": "Ubiquiti",
    "14988": "mikrotik",
    "2435": "brocade",
    "1641": "extreme",
    "601": "3com",
    "5624": "avaya",
    "318": "videx",
    "1271": "打印",
}

IF_TYPES = {
    1: "other",
    6: "ethernetCsmacd",
    24: "softwareLoopback",
    53: "propVirtual",
    54: "propMultiplexor",
    131: "tunnel",
    135: "l2vlan",
    136: "l3ipvlan",
    137: "l3ipipv6vlan",
    150: "mplsTunnel",
    161: "ieee80211",
    209: "ieee8023adLag",
    244: "portGroup",
}

STATUS_TEXT = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

SNMP_ERROR_TEXT = {
    1: "response too big",
    2: "no such name",
    3: "bad value",
    4: "read only",
    5: "general error",
    6: "no access",
    7: "wrong type",
    8: "wrong length",
    9: "wrong encoding",
}


def oid_index(oid: str, base: str) -> str | None:
    """Return the row index suffix for `oid` under `base`, or None."""
    if not oid.startswith(base + "."):
        return None
    return oid[len(base) + 1 :]


def walk_pairs(rows: list[tuple[str, object]], base: str) -> dict[str, object]:
    """Convert a walk of `base` into {index_suffix: value}."""
    out: dict[str, object] = {}
    for oid, value in rows:
        idx = oid_index(oid, base)
        if idx is not None:
            out[idx] = value
    return out


__all__ = [
    "SYSTEM_BASE",
    "SYS_DESCR",
    "SYS_OBJECT_ID",
    "SYS_UPTIME",
    "SYS_CONTACT",
    "SYS_NAME",
    "SYS_LOCATION",
    "SYS_SERVICES",
    "IF_DESCR",
    "IF_TYPE",
    "IF_NAME",
    "IF_ALIAS",
    "IF_SPEED",
    "IF_HIGH_SPEED",
    "IF_PHYS_ADDRESS",
    "IF_ADMIN_STATUS",
    "IF_OPER_STATUS",
    "IF_MTU",
    "IP_NET_TO_MEDIA",
    "DOT1D_TP_FDB_ADDRESS",
    "DOT1D_TP_FDB_PORT",
    "DOT1D_BASE_PORT_IF",
    "LLDP_REM_TABLE",
    "CDP_CACHE_ENTRY",
    "ENTERPRISE_VENDORS",
    "IF_TYPES",
    "STATUS_TEXT",
    "SNMP_ERROR_TEXT",
    "oid_index",
    "walk_pairs",
]
