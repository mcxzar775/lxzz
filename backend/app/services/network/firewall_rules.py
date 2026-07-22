from dataclasses import dataclass


@dataclass(frozen=True)
class FirewallRuleSpec:
    connection_id: int
    namespace: str
    host_veth: str
    namespace_veth: str
    host_address: str
    namespace_address: str
    remote_address: str
    remote_port: int
    remote_protocol: str
    socks_port: int | None
    client_ip_allowlist: tuple[str, ...]


@dataclass(frozen=True)
class NftRuleSet:
    namespace_table: str
    host_table: str
    namespace_script: str
    host_script: str


@dataclass(frozen=True)
class IptablesRuleSet:
    namespace_chains: tuple[str, str]
    host_chains: tuple[str, str, str, str]
    namespace_apply: tuple[tuple[str, ...], ...]
    namespace_cleanup: tuple[tuple[str, ...], ...]
    host_apply: tuple[tuple[str, ...], ...]
    host_cleanup: tuple[tuple[str, ...], ...]


def nft_rule_set(spec: FirewallRuleSpec) -> NftRuleSet:
    namespace_table = f"vpngate_n{spec.connection_id}"
    host_table = f"vpngate_h{spec.connection_id}"
    namespace_lines = [
        f"add table inet {namespace_table}",
        (
            f"add chain inet {namespace_table} output "
            "{ type filter hook output priority -100; policy drop; }"
        ),
        (
            f"add chain inet {namespace_table} input "
            "{ type filter hook input priority -100; policy drop; }"
        ),
        f'add rule inet {namespace_table} output oifname "lo" accept',
        (
            f"add rule inet {namespace_table} output "
            "ct state established,related accept"
        ),
        (
            f"add rule inet {namespace_table} output "
            f'oifname "{spec.namespace_veth}" ip daddr {spec.remote_address} '
            f"{spec.remote_protocol} dport {spec.remote_port} accept"
        ),
        f'add rule inet {namespace_table} output oifname "tun0" accept',
        f'add rule inet {namespace_table} input iifname "lo" accept',
        (
            f"add rule inet {namespace_table} input "
            "ct state established,related accept"
        ),
    ]
    if spec.socks_port is not None:
        namespace_lines.append(
            f"add rule inet {namespace_table} input "
            f'iifname "{spec.namespace_veth}" ip saddr {spec.host_address} '
            f"tcp dport {spec.socks_port} accept"
        )
    host_lines = [
        f"add table inet {host_table}",
        (
            f"add chain inet {host_table} postrouting "
            "{ type nat hook postrouting priority srcnat; policy accept; }"
        ),
        (
            f"add chain inet {host_table} forward "
            "{ type filter hook forward priority -100; policy accept; }"
        ),
    ]
    if spec.socks_port is not None:
        host_lines.extend(
            [
                (
                    f"add chain inet {host_table} prerouting "
                    "{ type nat hook prerouting priority dstnat; policy accept; }"
                ),
                (
                    f"add chain inet {host_table} input "
                    "{ type filter hook input priority -100; policy accept; }"
                ),
            ]
        )
        if spec.client_ip_allowlist:
            for source in spec.client_ip_allowlist:
                host_lines.append(
                    f"add rule inet {host_table} prerouting ip saddr {source} "
                    f"tcp dport {spec.socks_port} dnat ip to "
                    f"{spec.namespace_address}:{spec.socks_port}"
                )
        else:
            host_lines.append(
                f"add rule inet {host_table} prerouting "
                f"tcp dport {spec.socks_port} dnat ip to "
                f"{spec.namespace_address}:{spec.socks_port}"
            )
    host_lines.extend(
        [
            (
                f"add rule inet {host_table} postrouting "
                f"ip saddr {spec.namespace_address} ip daddr {spec.remote_address} "
                f"{spec.remote_protocol} dport {spec.remote_port} masquerade"
            ),
            (
                f"add rule inet {host_table} forward "
                f'iifname "{spec.host_veth}" ip saddr {spec.namespace_address} '
                f"ip daddr {spec.remote_address} {spec.remote_protocol} "
                f"dport {spec.remote_port} ct state new,established accept"
            ),
            (
                f"add rule inet {host_table} forward "
                f'oifname "{spec.host_veth}" ip saddr {spec.remote_address} '
                f"ip daddr {spec.namespace_address} {spec.remote_protocol} "
                f"sport {spec.remote_port} ct state established,related accept"
            ),
        ]
    )
    if spec.socks_port is not None:
        host_lines.extend(
            [
                (
                    f"add rule inet {host_table} postrouting "
                    f"ip daddr {spec.namespace_address} tcp dport {spec.socks_port} "
                    f"snat ip to {spec.host_address}"
                ),
                (
                    f"add rule inet {host_table} forward "
                    f'ip daddr {spec.namespace_address} oifname "{spec.host_veth}" '
                    f"tcp dport {spec.socks_port} ct state new,established accept"
                ),
                (
                    f"add rule inet {host_table} forward "
                    f'ip saddr {spec.namespace_address} iifname "{spec.host_veth}" '
                    "ct state established,related accept"
                ),
                (
                    f"add rule inet {host_table} input "
                    f"tcp dport {spec.socks_port} drop"
                ),
            ]
        )
    return NftRuleSet(
        namespace_table=namespace_table,
        host_table=host_table,
        namespace_script="\n".join(namespace_lines) + "\n",
        host_script="\n".join(host_lines) + "\n",
    )


def iptables_rule_set(spec: FirewallRuleSpec) -> IptablesRuleSet:
    identifier = str(spec.connection_id)
    namespace_output = f"VGO{identifier}"
    namespace_input = f"VGI{identifier}"
    host_prerouting = f"VGP{identifier}"
    host_postrouting = f"VGS{identifier}"
    host_forward = f"VGF{identifier}"
    host_input = f"VGD{identifier}"
    namespace_apply: list[tuple[str, ...]] = [
        ("-N", namespace_output),
        ("-A", namespace_output, "-o", "lo", "-j", "ACCEPT"),
        (
            "-A",
            namespace_output,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ),
        (
            "-A",
            namespace_output,
            "-o",
            spec.namespace_veth,
            "-d",
            spec.remote_address,
            "-p",
            spec.remote_protocol,
            "--dport",
            str(spec.remote_port),
            "-j",
            "ACCEPT",
        ),
        ("-A", namespace_output, "-o", "tun0", "-j", "ACCEPT"),
        ("-A", namespace_output, "-j", "DROP"),
        ("-N", namespace_input),
        ("-A", namespace_input, "-i", "lo", "-j", "ACCEPT"),
        (
            "-A",
            namespace_input,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ),
    ]
    if spec.socks_port is not None:
        namespace_apply.append(
            (
                "-A",
                namespace_input,
                "-i",
                spec.namespace_veth,
                "-s",
                spec.host_address,
                "-p",
                "tcp",
                "--dport",
                str(spec.socks_port),
                "-j",
                "ACCEPT",
            )
        )
    namespace_apply.extend(
        [
            ("-A", namespace_input, "-j", "DROP"),
            ("-I", "OUTPUT", "1", "-j", namespace_output),
            ("-I", "INPUT", "1", "-j", namespace_input),
        ]
    )
    namespace_cleanup = (
        ("-D", "OUTPUT", "-j", namespace_output),
        ("-D", "INPUT", "-j", namespace_input),
        ("-F", namespace_output),
        ("-X", namespace_output),
        ("-F", namespace_input),
        ("-X", namespace_input),
    )
    host_apply: list[tuple[str, ...]] = [
        ("-t", "nat", "-N", host_prerouting),
    ]
    if spec.socks_port is not None:
        if spec.client_ip_allowlist:
            for source in spec.client_ip_allowlist:
                host_apply.append(
                    (
                        "-t",
                        "nat",
                        "-A",
                        host_prerouting,
                        "-s",
                        source,
                        "-p",
                        "tcp",
                        "--dport",
                        str(spec.socks_port),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        f"{spec.namespace_address}:{spec.socks_port}",
                    )
                )
        else:
            host_apply.append(
                (
                    "-t",
                    "nat",
                    "-A",
                    host_prerouting,
                    "-p",
                    "tcp",
                    "--dport",
                    str(spec.socks_port),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{spec.namespace_address}:{spec.socks_port}",
                )
            )
    host_apply.extend(
        [
            ("-t", "nat", "-I", "PREROUTING", "1", "-j", host_prerouting),
            ("-N", host_input),
        ]
    )
    if spec.socks_port is not None:
        host_apply.append(
            (
                "-A",
                host_input,
                "-p",
                "tcp",
                "--dport",
                str(spec.socks_port),
                "-j",
                "DROP",
            )
        )
    host_apply.extend(
        [
            ("-I", "INPUT", "1", "-j", host_input),
            ("-t", "nat", "-N", host_postrouting),
            (
                "-t",
                "nat",
                "-A",
                host_postrouting,
                "-s",
                spec.namespace_address,
                "-d",
                spec.remote_address,
                "-p",
                spec.remote_protocol,
                "--dport",
                str(spec.remote_port),
                "-j",
                "MASQUERADE",
            ),
        ]
    )
    if spec.socks_port is not None:
        host_apply.append(
            (
                "-t",
                "nat",
                "-A",
                host_postrouting,
                "-d",
                spec.namespace_address,
                "-p",
                "tcp",
                "--dport",
                str(spec.socks_port),
                "-j",
                "SNAT",
                "--to-source",
                spec.host_address,
            )
        )
    host_apply.extend(
        [
            ("-t", "nat", "-I", "POSTROUTING", "1", "-j", host_postrouting),
            ("-N", host_forward),
            (
                "-A",
                host_forward,
                "-i",
                spec.host_veth,
                "-s",
                spec.namespace_address,
                "-d",
                spec.remote_address,
                "-p",
                spec.remote_protocol,
                "--dport",
                str(spec.remote_port),
                "-m",
                "conntrack",
                "--ctstate",
                "NEW,ESTABLISHED",
                "-j",
                "ACCEPT",
            ),
            (
                "-A",
                host_forward,
                "-o",
                spec.host_veth,
                "-s",
                spec.remote_address,
                "-d",
                spec.namespace_address,
                "-p",
                spec.remote_protocol,
                "--sport",
                str(spec.remote_port),
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ),
        ]
    )
    if spec.socks_port is not None:
        host_apply.extend(
            [
                (
                    "-A",
                    host_forward,
                    "-d",
                    spec.namespace_address,
                    "-o",
                    spec.host_veth,
                    "-p",
                    "tcp",
                    "--dport",
                    str(spec.socks_port),
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "NEW,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ),
                (
                    "-A",
                    host_forward,
                    "-s",
                    spec.namespace_address,
                    "-i",
                    spec.host_veth,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ),
            ]
        )
    host_apply.append(("-I", "FORWARD", "1", "-j", host_forward))
    host_cleanup = (
        ("-t", "nat", "-D", "PREROUTING", "-j", host_prerouting),
        ("-t", "nat", "-D", "POSTROUTING", "-j", host_postrouting),
        ("-D", "FORWARD", "-j", host_forward),
        ("-D", "INPUT", "-j", host_input),
        ("-t", "nat", "-F", host_prerouting),
        ("-t", "nat", "-X", host_prerouting),
        ("-t", "nat", "-F", host_postrouting),
        ("-t", "nat", "-X", host_postrouting),
        ("-F", host_forward),
        ("-X", host_forward),
        ("-F", host_input),
        ("-X", host_input),
    )
    return IptablesRuleSet(
        namespace_chains=(namespace_output, namespace_input),
        host_chains=(host_prerouting, host_postrouting, host_forward, host_input),
        namespace_apply=tuple(namespace_apply),
        namespace_cleanup=namespace_cleanup,
        host_apply=tuple(host_apply),
        host_cleanup=host_cleanup,
    )
