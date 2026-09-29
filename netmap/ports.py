"""Well-known port registry + service risk classes.

The table is written as a compact pipe-delimited spec (parsed once at import,
strictly) so it stays readable and auditable:

    <port> | <name> | <category> | <encryption> | <exposure-risk>

* ``category`` groups services for rules and for the dashboard legend.
* ``encryption`` is what a *correct* deployment of that service uses; a live
  service that does not match it becomes an exposure finding.
* ``exposure-risk`` 0..3 = how bad this port is if a user/wan zone can reach it.
"""

from __future__ import annotations

import re

_SPEC = """
7 | echo | infra | none | 1
17 | qotd | infra | none | 1
19 | chargen | infra | none | 2
20 | ftp-data | file | none | 2
21 | ftp | file | none | 3
22 | ssh | management | ssh | 0
23 | telnet | management | none | 3
25 | smtp | mail | none | 1
37 | time | infra | none | 1
49 | tacacs | directory | none | 3
53 | dns | naming | none | 1
69 | tftp | file | none | 3
79 | finger | infra | none | 2
80 | http | web | none | 2
81 | http-alt | web | none | 2
88 | kerberos-sec | directory | other | 1
102 | iso-tsap | industrial | none | 3
109 | pop2 | mail | none | 3
110 | pop3 | mail | none | 3
111 | rpcbind | infra | none | 2
113 | ident | infra | none | 1
119 | nntp | collaboration | none | 2
123 | ntp | infra | none | 0
135 | msrpc | infra | none | 2
137 | netbios-ns | naming | none | 2
138 | netbios-dgm | file | none | 2
139 | netbios-ssn | file | none | 3
143 | imap | mail | none | 3
161 | snmp | management | none | 3
162 | snmptrap | management | none | 1
179 | bgp | infra | other | 2
199 | smux | management | none | 2
259 | esro-gen | industrial | none | 1
389 | ldap | directory | none | 2
401 | ups | infra | none | 2
427 | svrloc | infra | none | 1
443 | https | web | tls | 0
445 | microsoft-ds | file | none | 3
464 | kpasswd5 | directory | other | 1
465 | smtps | mail | tls | 0
500 | isakmp | infra | none | 1
512 | rexe | management | none | 3
513 | rlogin | management | none | 3
514 | syslog | infra | none | 0
515 | printer | collaboration | none | 2
520 | rip | infra | none | 2
548 | afp | file | none | 2
554 | rtsp | collaboration | none | 1
563 | snews | mail | tls | 0
587 | submission | mail | tls | 0
593 | rpchttp-epmap | infra | none | 2
623 | ipmi | management | none | 3
631 | ipp | collaboration | none | 1
636 | ldaps | directory | tls | 0
691 | resvc | infra | none | 2
873 | rsync | file | none | 1
888 | webman | management | none | 2
901 | samba-swat | management | none | 3
990 | ftps | file | tls | 1
992 | telnets | management | tls | 0
993 | imaps | mail | tls | 0
995 | pop3s | mail | tls | 0
1025 | lotus-notes | collaboration | none | 1
1080 | socks | remote | none | 2
1194 | venus1 | infra | none | 1
1352 | lotus-notes | collaboration | none | 2
1433 | ms-sql-s | database | none | 3
1521 | oracle-tns | database | none | 3
1719 | h323gatecall | collaboration | none | 2
1720 | h323callsig | collaboration | none | 2
1723 | pptp | remote | none | 2
1801 | nms-topo | management | none | 1
1863 | msnm | messaging | none | 1
1883 | mqtt | industrial | none | 2
1900 | ssdp | naming | none | 2
2000 | cisco-sccp | voip | none | 2
2002 | glogind | management | none | 2
2049 | nfs | file | none | 3
2105 | rfb | remote | none | 3
2181 | zookeeper | database | none | 2
2222 | ssh-alt | management | ssh | 1
2305 | pehelp | infra | none | 2
2323 | telnet-alt | management | none | 3
2375 | docker-api | management | none | 3
2376 | docker-tls | management | tls | 1
2379 | etcd | database | none | 3
2601 | zebra | infra | none | 2
2605 | bgpd | infra | none | 2
3000 | remote-anything | remote | none | 2
3001 | nessus | management | tls | 2
3128 | squid | proxy | none | 2
3260 | mcafee-ahp | infra | none | 1
3268 | microsoft-gc | directory | none | 2
3269 | microsoft-gc-ssl | directory | tls | 0
3283 | net-assistant | management | none | 3
3306 | mysql | database | none | 3
3324 | sdtportmap | infra | none | 2
3333 | dec-notes | collaboration | none | 1
3351 | btrieve | database | none | 2
3369 | dialpad | voip | none | 1
3389 | ms-wbt-server | remote | none | 3
3476 | nspinfra | monitoring | none | 1
3493 | tls-ldap | directory | tls | 0
3517 | 802-11-iapp | infra | none | 2
3551 | apc-nmc2 | management | none | 3
3632 | mds-transmanager | infra | none | 1
3689 | rrpp | infra | none | 1
3690 | sqlnet | database | none | 2
3703 | adobe-admin | web | none | 1
3737 | xpi | infra | none | 1
3766 | dnsix-sec | naming | none | 1
3829 | hp-collector | management | none | 1
3878 | hp-dataprot | monitoring | none | 1
3880 | ibm-mq | messaging | none | 2
3905 | mupdate | mail | none | 1
3918 | ups-old-1 | infra | none | 1
3945 | emcagent | management | none | 2
3971 | lanrevserver | management | none | 2
4000 | terabase | database | none | 2
4045 | langpaths | infra | none | 1
4126 | asna-address | database | tls | 0
4129 | nuo-keeper | infra | none | 1
4224 | xtell | remote | none | 3
4343 | whoispp | infra | none | 0
4444 | ntlabs-remote | remote | none | 3
4445 | ninjatrap | infra | none | 1
4446 | npp | infra | none | 1
4449 | plgstatus | infra | none | 1
4557 | faxinfra | infra | none | 1
4662 | distcc | management | none | 2
4739 | ipfix | monitoring | none | 0
4848 | appserv-http | web | none | 2
4899 | radmin | remote | none | 3
5000 | upnp | infra | none | 2
5001 | commplex-main | infra | none | 2
5033 | rfe | infra | none | 1
5050 | multimedia-conference | collaboration | none | 1
5060 | sip | voip | none | 1
5061 | sips | voip | tls | 0
5080 | onboarding | provisioning | none | 1
5087 | ndmp | file | none | 2
5100 | hpll-ncp | management | none | 1
5190 | icq | messaging | none | 1
5222 | xmpp-client | messaging | tls | 0
5269 | xmpp-server | messaging | tls | 0
5353 | mdns | naming | none | 1
5357 | ws-discovery | naming | none | 1
5404 | pcduo | directory | none | 2
5405 | pcduo-old | directory | none | 2
5432 | postgresql | database | none | 3
5500 | remote1 | remote | none | 1
5510 | secure-mgmt-access | management | none | 2
5544 | westell-connect | infra | none | 1
5550 | sdlog | infra | none | 1
5555 | freeciv-server | infra | none | 2
5566 | iselect-rdl | infra | none | 1
5631 | pcanywhere-status | remote | none | 3
5632 | pcanywhere-data | remote | none | 3
5666 | nrpe | monitoring | none | 2
5671 | amqp | messaging | none | 1
5672 | amqps | messaging | tls | 0
5678 | ra-http | infra | none | 1
5718 | dpm-old | management | none | 1
5723 | wafer-check | infra | none | 1
5730 | panorama-admin | management | none | 2
5801 | vnc-1 | remote | none | 3
5810 | pfweb | management | none | 1
5811 | dm | infra | none | 1
5815 | silc | messaging | other | 0
5822 | hpwebjam | management | none | 1
5859 | wherehoo | monitoring | none | 1
5862 | java-messaging | messaging | none | 1
5868 | whoispp-plus | infra | none | 0
5869 | whoaa | infra | none | 1
5877 | whoamiup | infra | none | 1
5882 | scient-crdriver | monitoring | none | 1
5900 | vnc | remote | none | 3
5901 | vnc-1 | remote | none | 3
5902 | vnc-2 | remote | none | 3
5903 | vnc-3 | remote | none | 3
5906 | vnc-6 | remote | none | 3
5910 | cm | messaging | none | 1
5911 | cncp | infra | none | 1
5915 | ambit-lm | management | none | 1
5959 | wsman-alt | management | none | 1
5962 | ncdb | infra | none | 1
5963 | indy | infra | none | 1
5985 | wsman | management | none | 3
5986 | wsmans | management | tls | 0
5987 | wbem-rm | management | none | 2
5988 | wbem-ssl | management | tls | 0
5989 | wbem-safe | management | none | 2
5998 | scard | file | none | 2
6000 | x11 | remote | none | 3
6001 | conlpsrv | infra | none | 1
6059 | x11-1 | remote | none | 3
6101 | brcd-sfi-mgmt | management | none | 2
6112 | supd | infra | none | 1
6123 | backup-server | file | none | 2
6156 | matrix-net2 | infra | none | 1
6200 | lm-oauth | monitoring | none | 1
6346 | glrpc | infra | none | 1
6379 | redis | database | none | 3
6443 | kube-api | management | tls | 2
6514 | gnutec-sftp | file | none | 2
6666 | irc | messaging | none | 2
6667 | irc | messaging | none | 2
6668 | irc | messaging | none | 2
6669 | irc | messaging | none | 2
6839 | udp-port-snmp | management | none | 2
6969 | thot-crm | infra | none | 1
7000 | afs3-fileserver | file | none | 2
7001 | afs3-callback | infra | none | 1
7002 | afs3-prserver | directory | none | 2
7004 | afs3-vlserver | file | none | 2
7007 | motivex-client | infra | none | 1
7010 | silc | management | none | 1
7070 | arcp | infra | none | 1
7100 | font-service | infra | none | 1
7161 | cabsm | management | none | 1
7200 | dlip | infra | none | 1
7443 | oracle-em-mgr | management | tls | 0
7512 | perf-profile | infra | none | 1
7543 | pplsvr | monitoring | none | 1
7628 | mobilep2p | infra | none | 1
7634 | supfile | infra | none | 1
7648 | team-coherence | industrial | none | 2
7741 | scriptview | management | none | 1
7778 | office-tools | infra | none | 1
7911 | lmsmtp | infra | none | 1
7920 | site-engine | infra | none | 1
7921 | viewdrop | collaboration | none | 1
7937 | nsca | monitoring | none | 2
7938 | unlmsp | infra | none | 1
7999 | ics-relay | infra | none | 1
8000 | http-alt | web | none | 2
8001 | vcom-tunnel | remote | none | 2
8002 | teradata | database | none | 2
8007 | ajp12 | web | none | 1
8008 | http | web | none | 2
8009 | ajp13 | web | none | 2
8010 | ray-link | infra | none | 1
8020 | intuit-eps2 | monitoring | none | 1
8022 | oa-system | management | none | 1
8025 | world-mail-admin | management | none | 3
8044 | c-dns | security | tls | 0
8080 | http-proxy | web | none | 2
8081 | blackice-ipsm | security | none | 2
8082 | blackice-alerts | security | none | 1
8083 | us-srv | web | none | 2
8085 | privoxy | proxy | none | 2
8088 | radan-http | web | none | 2
8089 | accesereplication | infra | none | 1
8090 | rapid-diag | management | none | 1
8093 | routematch | infra | none | 1
8099 | timbuktu-pro | remote | none | 3
8100 | print-server-jetdirect | collaboration | none | 2
8118 | torproxy | proxy | none | 2
8181 | pulse-secure | remote | none | 2
8192 | privoxy-alt | proxy | none | 1
8222 | vmware-fdm | management | ssh | 1
8243 | omnilock | industrial | none | 1
8300 | tmi | monitoring | none | 1
8333 | cloud9 | infra | none | 1
8383 | m2ts | collaboration | none | 1
8400 | network-snapshots | monitoring | none | 1
8443 | https-alt | web | tls | 0
8444 | ssl-nsp | security | tls | 0
8450 | nm-server | infra | none | 1
8460 | vmware-mgmt | web | tls | 1
8471 | vmware-ovim | infra | none | 1
8472 | vxlan-overlay | infra | none | 1
8675 | java-message-bus | messaging | none | 1
8686 | lotus-notes-web | web | none | 1
8701 | ft-secure | remote | tls | 0
8800 | rtsserver | infra | none | 1
8888 | ddi-snmp-1 | messaging | none | 1
8889 | ddi-rt1 | messaging | none | 1
8899 | ofexmgr | infra | none | 1
8994 | bcep-ssl | monitoring | tls | 0
9000 | cslistener | web | none | 2
9001 | tor-orport | infra | none | 2
9002 | intelmesage | infra | none | 1
9003 | realmonitor | monitoring | none | 1
9040 | grid-storage | database | none | 1
9060 | snmptunnel | management | none | 1
9080 | glrpc | infra | none | 1
9088 | open-replication | infra | none | 1
9090 | zeppelin | web | none | 2
9091 | xmlsec-tls | infra | tls | 0
9092 | snmp-proxy | management | none | 2
9093 | open-replication-db | infra | none | 1
9099 | prometheus | monitoring | none | 2
9100 | jetdirect-printer | collaboration | none | 2
9101 | jetdirect-b-printer | collaboration | none | 2
9102 | jetdirect-c-printer | collaboration | none | 2
9103 | hepatitis | infra | none | 1
9111 | dragon-lsp | infra | none | 1
9152 | ms-wbt-server-1 | remote | none | 2
9160 | dolphin-db | database | none | 1
9200 | elasticsearch | database | none | 3
9201 | wrs-http | web | none | 1
9207 | vxlan-control | infra | none | 1
9290 | veritas-nav | file | none | 1
9503 | boss-db | database | none | 1
9594 | mesl-water | infra | none | 1
9595 | pdr-mess | infra | none | 1
9876 | session-daemon | remote | none | 1
9898 | monkey-logically | infra | none | 1
9900 | iet-announcement | infra | none | 1
9911 | sparse-testing | infra | none | 1
9999 | abyss-web | web | none | 2
10000 | networker-backup | file | none | 3
10001 | scoki | infra | none | 1
10050 | zabbix-agent | monitoring | none | 2
10051 | zabbix-trapper | monitoring | none | 2
10080 | mandersoft | infra | none | 1
10128 | backup-express | file | none | 1
10180 | knowbotix | infra | none | 1
10243 | oximeter | infra | none | 1
11111 | virtdb | database | none | 2
11211 | memcache | database | none | 3
11332 | bulatwist | infra | none | 1
11373 | nfc | infra | none | 1
12076 | grant-asmsp | infra | none | 1
12345 | netbus | infra | none | 2
13000 | step-scm-mgmt | management | none | 1
13092 | jcp-client | infra | none | 1
14000 | scotty-lite | infra | none | 1
15002 | oradb-data-guard | database | none | 1
15003 | hydas | web | none | 1
15660 | bexr | file | none | 1
15672 | rabbitmq-mgmt | management | none | 3
16080 | osxwebim | messaging | none | 1
16113 | unknown | infra | none | 1
16992 | intel-amt | management | none | 3
16993 | intel-amt-tls | management | tls | 1
17185 | ssh-passwd-bot | infra | none | 2
17500 | dropbox-lan-sync | file | none | 1
18000 | network-agent | monitoring | none | 1
18185 | infspire | infra | none | 1
19315 | mac-address-serial | infra | none | 1
19780 | notatech-dbx | infra | none | 1
19801 | bsd-ucr | infra | none | 1
20000 | dnp3 | industrial | none | 3
20001 | microzone | infra | none | 1
20002 | sanai-assist | infra | none | 1
20221 | virus-push | infra | none | 1
20222 | ipulse-diag | infra | none | 1
21571 | device3 | infra | none | 1
22453 | infobright | database | none | 1
22939 | alcatel-admin | management | none | 2
23515 | fms | monitoring | none | 1
25793 | cnc | infra | none | 1
26208 | suna | infra | none | 1
26260 | wpl-analytics | monitoring | none | 1
27017 | mongodb | database | none | 3
27018 | mongodb-2 | database | none | 2
27019 | jpodc2 | infra | none | 1
27374 | ramon | infra | none | 2
28050 | filecope | infra | none | 1
30000 | terabase-dbd | database | none | 1
31038 | channel-key | infra | none | 1
31337 | back-orifice | infra | none | 3
32768 | filemaker | database | none | 2
32769 | solaris-rpc | infra | none | 1
33354 | ocs-lite | infra | none | 1
34573 | prni-pipe | infra | none | 1
35500 | epic-script | infra | none | 1
37600 | epson-ix1 | printer | none | 1
38080 | lighttpd-http | web | none | 2
38292 | netdms | infra | none | 1
40000 | prioricity | infra | none | 1
40193 | tsaf | infra | none | 1
41523 | massira | infra | none | 1
42510 | ca-rp-monitor | infra | none | 1
44176 | unknown | infra | none | 1
44574 | unknown | infra | none | 1
49152 | unknown | infra | none | 1
49153 | unknown | infra | none | 1
49154 | unknown | infra | none | 1
49999 | hyper-io | infra | none | 1
50000 | ibm-db2 | database | none | 2
50001 | unknown | infra | none | 1
50002 | ibm-db2-2 | database | none | 2
50003 | cmgr-daemon | management | none | 1
50006 | login-lupin | infra | none | 1
54311 | unknown | infra | none | 1
54792 | tutosa | infra | none | 1
55440 | siemens-gsm | industrial | none | 2
57797 | hcl-encryption | infra | none | 1
60020 | backup-server | file | none | 2
60443 | https-alt | web | tls | 0
64623 | emc-xserv | management | none | 2
65000 | mach-bps | infra | none | 1
"""

_UDP_SPEC = """
53 | domain | naming | none | 1
67 | dhcp-server | infra | none | 1
68 | dhcp-client | infra | none | 0
69 | tftp | file | none | 3
111 | rpcbind | infra | none | 2
123 | ntp | infra | none | 0
137 | netbios-ns | naming | none | 2
138 | netbios-dgm | file | none | 2
161 | snmp | management | none | 3
162 | snmptrap | management | none | 1
177 | xdmcp | management | none | 3
389 | ldap | directory | none | 2
427 | svrloc | infra | none | 1
464 | kpasswd5 | directory | other | 1
500 | isakmp | infra | other | 1
514 | syslog | infra | none | 0
518 | hsrp | infra | none | 0
520 | rip | infra | none | 2
546 | dhcpv6-client | infra | none | 0
547 | dhcpv6-server | infra | none | 1
623 | asf-rmcp+ | management | none | 3
626 | serverloc | infra | none | 1
996 | mk-td-volume | infra | none | 1
997 | vsi-server | monitoring | none | 1
1000 | cadlock | infra | none | 1
1005 | java-obj | infra | none | 1
1026 | c1222-result | infra | none | 1
1080 | socks | remote | none | 2
1394 | hp-policy-agent | management | none | 2
1434 | ms-sql-m-monitor | database | none | 3
1645 | radius-old | directory | none | 3
1646 | radius-acct-old | directory | none | 2
1701 | l2tp | remote | other | 1
1718 | h323gatestat | collaboration | none | 1
1719 | h323gatecall | collaboration | none | 2
1720 | h323-callsig | collaboration | none | 2
1812 | radius | directory | other | 2
1813 | radius-acct | directory | other | 1
1900 | ssdp | naming | none | 2
1993 | snmp-trap | infra | none | 1
2000 | cisco-sccp | voip | none | 2
2002 | gc-log-dump | monitoring | none | 1
2049 | nfs | file | none | 3
2103 | axis-software-blink | infra | none | 1
2223 | infocore | infra | none | 1
2327 | net-app-icp | file | none | 2
2332 | sns-ias | directory | none | 2
2600 | hp-status | monitoring | none | 1
2766 | one-lap | infra | none | 1
3052 | power-chute-plus | management | none | 2
3130 | hp-cxp-xml | management | none | 1
3283 | net-assistant | management | none | 3
3456 | vat | collaboration | none | 1
3457 | vat-control | collaboration | none | 1
3632 | ndb-ss | database | none | 1
3703 | adobe-services | web | none | 1
4353 | deviceshare-i | management | none | 1
4444 | remote6 | remote | none | 3
4500 | ipsec-nat-t | infra | ipsec | 0
4754 | bfn-networks | monitoring | none | 1
5060 | sip | voip | none | 2
5353 | mdns | naming | none | 1
5355 | lldp | naming | none | 0
5631 | pcanywhere-status | remote | none | 3
5632 | pcanywhere-data | remote | none | 3
5678 | remote6-2 | remote | none | 2
60064 | bit-torrent | infra | none | 1
62233 | gwy-opt-bus | industrial | none | 2
47808 | bacnet | industrial | none | 3
49152 | hilti | infra | none | 1
49181 | lava-mcs | infra | none | 1
49999 | luxsource | infra | none | 1
50000 | ibm-db2 | database | none | 2
53589 | slicer | monitoring | none | 1
5683 | coap | industrial | none | 2
5684 | coaps | industrial | tls | 0
5685 | coap-nosec | industrial | none | 2
7400 | rt-discovery | infra | none | 1
31038 | ka-da-protocol | infra | none | 1
49160 | binf | infra | none | 1
49161 | binf-ssl | infra | tls | 0
"""


ENC_CLASSES = ("none", "tls", "ssh", "other", "ipsec", "unknown")


def _parse_spec(text: str) -> dict[int, tuple[str, str, str, int]]:
    """Parse ``port | name | category | encryption | risk`` lines. Strict: a bad
    line is a shipping bug, so it raises at import rather than being skipped."""
    table: dict[int, tuple[str, str, str, int]] = {}
    for lineno, line in enumerate(text.strip().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 5:
            raise ValueError(f"ports spec line {lineno}: expected 5 pipe-separated fields, got {line!r}")
        port_s, name, category, enc, risk_s = parts
        try:
            port, risk = int(port_s), int(risk_s)
        except ValueError as exc:
            raise ValueError(f"ports spec line {lineno}: {exc}") from None
        if not 1 <= port <= 65535:
            raise ValueError(f"ports spec line {lineno}: port {port} out of range")
        if enc not in ENC_CLASSES:
            raise ValueError(f"ports spec line {lineno}: bad encryption class {enc!r}")
        if not 0 <= risk <= 3:
            raise ValueError(f"ports spec line {lineno}: risk must be 0..3")
        if not re.fullmatch(r"[a-z0-9.+-]+", name):
            raise ValueError(f"ports spec line {lineno}: bad service name {name!r}")
        if port in table:
            raise ValueError(f"ports spec line {lineno}: duplicate port {port}")
        table[port] = (name, category, enc, risk)
    return table


PORTS = _parse_spec(_SPEC)
UDP_PORTS = _parse_spec(_UDP_SPEC)

# management/remote-access surface that must never face untrusted zones
MANAGEMENT_PORTS = frozenset({22, 23, 80, 443, 161, 162, 623, 830, 3389, 5985, 5986, 8080, 8443, 9003, 10000, 15672, 16992})
PLAINTEXT_PORTS = frozenset(p for p, v in PORTS.items() if v[2] == "none" and v[3] >= 2)
CREDENTIAL_RISK_PORTS = frozenset({23, 21, 69, 161, 389, 445, 1433, 1521, 3306, 5432, 5900, 6379, 11211, 27017, 9200, 15672})
DATABASE_PORTS = frozenset(p for p, v in PORTS.items() if v[1] == "database")
REMOTE_PORTS = frozenset(p for p, v in PORTS.items() if v[1] == "remote")
INDUSTRIAL_PORTS = frozenset(p for p, v in list(PORTS.items()) + list(UDP_PORTS.items()) if v[1] == "industrial")


def port_info(port: int, protocol: str = "tcp") -> tuple[str, str, str, int]:
    table = PORTS if protocol == "tcp" else UDP_PORTS
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    return table.get(port, (f"unknown/{port}", "infra", "unknown", 1))


def port_name(port: int, protocol: str = "tcp") -> str:
    return port_info(port, protocol)[0]


def port_category(port: int, protocol: str = "tcp") -> str:
    return port_info(port, protocol)[1]


def port_risk(port: int, protocol: str = "tcp") -> int:
    return port_info(port, protocol)[3]


def expected_encryption(port: int, protocol: str = "tcp") -> str:
    return port_info(port, protocol)[2]


def is_plaintext(port: int, protocol: str = "tcp") -> bool:
    """True when the standard deployment of this service is unencrypted."""
    return port_info(port, protocol)[2] == "none"


def ports_for_category(category: str) -> set[int]:
    return {p for p, v in PORTS.items() if v[1] == category}


# Ports that are actually listening on real enterprise hosts. The default scan
# list has to cover these first: a risk-ordered list would skip tcp/443 and
# tcp/22 (both "encrypted, therefore low risk") and the scan would miss the
# majority of the estate.
COMMON_TCP = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 161, 179, 389, 443, 445, 465, 514, 515,
    587, 623, 631, 636, 749, 873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883,
    2049, 2181, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 3690, 4045, 4369, 5000, 5060, 5432,
    5560, 5601, 5665, 5671, 5672, 5900, 5985, 5986, 6379, 6443, 7000, 7001, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 15672,
    27017, 27018, 49152, 50000, 50070, 61616,
]

# Audit-relevant ports that must never be missing from a scan even if nobody
# expects them to be open (this is where the risk ordering earns its keep).
AUDIT_TCP = [
    19, 20, 49, 69, 88, 102, 109, 113, 177, 371, 389, 427, 488, 497, 513, 514, 543, 544, 548,
    636, 749, 860, 873, 992, 1026, 1234, 1457, 1521, 2049, 2121, 2222, 2301, 2383, 2638, 3299,
    3306, 3389, 3551, 4045, 4333, 4444, 4445, 4500, 5000, 5010, 5060, 5190, 5357, 5432, 5555,
    5632, 5666, 5718, 5800, 5801, 5900, 5901, 5988, 6000, 6001, 6112, 6502, 6666, 7001, 7161,
    7162, 7163, 8000, 8080, 8181, 8443, 8888, 8900, 9000, 9040, 9041, 9100, 9111, 9200, 9500,
    9503, 9999, 10000, 10161, 11371, 12076, 12345, 13782, 17185, 20021, 22222, 26214, 27017,
    27374, 31337, 32764, 49152, 50070, 50081, 50214, 53135, 60177, 64738,
]


def top_ports(count: int = 100, *, order: str = "common") -> list[int]:
    """Default TCP port list for a scan.

    `order="common"` starts from what is usually listening and backfills with
    the riskiest unlisted ports; `order="risk"` is the pure audit view (used by
    docs and tests to answer "what should a scanner never miss").
    """
    count = max(1, int(count))
    if order == "risk":
        ranked = sorted(PORTS, key=lambda p: (-PORTS[p][3], p))
        return sorted(ranked[:count])
    ordered: list[int] = []
    seen: set[int] = set()
    for port in COMMON_TCP + AUDIT_TCP:
        if port in PORTS and port not in seen:
            seen.add(port)
            ordered.append(port)
    if len(ordered) < count:
        ranked = sorted(PORTS, key=lambda p: (-PORTS[p][3], p))
        for port in ranked:
            if len(ordered) >= count:
                break
            if port not in seen:
                seen.add(port)
                ordered.append(port)
    return sorted(ordered[:count])


__all__ = [
    "PORTS",
    "UDP_PORTS",
    "MANAGEMENT_PORTS",
    "PLAINTEXT_PORTS",
    "CREDENTIAL_RISK_PORTS",
    "DATABASE_PORTS",
    "REMOTE_PORTS",
    "INDUSTRIAL_PORTS",
    "port_info",
    "port_name",
    "port_category",
    "port_risk",
    "expected_encryption",
    "is_plaintext",
    "ports_for_category",
    "top_ports",
]
