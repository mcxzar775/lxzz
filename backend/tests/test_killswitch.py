from dataclasses import dataclass, field

import pytest

from app.services.network import CommandResult, NetworkCommand, NetworkOperation
from app.services.network.executor import RealNetworkExecutor
from app.services.network.firewall_rules import iptables_rule_set, nft_rule_set
from app.services.network.killswitch import (
    KillSwitchManager,
    KillSwitchOperationError,
    KillSwitchPlan,
    build_killswitch_plan,
    killswitch_apply_command,
)


@dataclass
class FirewallExecutor:
    apply_code: int = 0
    remove_code: int = 0
    status_code: int = 0
    backend: str = "nftables"
    commands: list[NetworkCommand] = field(default_factory=list)

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        assert 0 < timeout_seconds <= 120
        self.commands.append(command)
        if command.operation is NetworkOperation.KILLSWITCH_APPLY:
            return CommandResult(command, self.apply_code, "", "")
        if command.operation is NetworkOperation.KILLSWITCH_REMOVE:
            return CommandResult(command, self.remove_code, "", "")
        if command.operation is NetworkOperation.KILLSWITCH_STATUS:
            output = self.backend if self.status_code == 0 else ""
            return CommandResult(command, self.status_code, output, "")
        raise AssertionError(f"unexpected operation: {command.operation}")


def _plan() -> KillSwitchPlan:
    return build_killswitch_plan(
        2,
        node_id=9,
        remote_address="8.8.8.8",
        remote_port=1194,
        remote_protocol="udp",
        socks_port=21002,
        client_ip_allowlist=("198.51.100.7/32", "203.0.113.0/24"),
    )


def test_plan_uses_deterministic_namespace_addresses_and_safe_command() -> None:
    plan = build_killswitch_plan(
        2,
        node_id=9,
        remote_address="8.8.8.8",
        remote_port=443,
        remote_protocol="tcp",
        socks_port=21002,
        client_ip_allowlist=("198.51.100.7",),
        backend="nftables",
    )

    assert plan.namespace == "lxvpn-2"
    assert plan.host_veth == "lvh2"
    assert plan.namespace_veth == "lvn2"
    assert plan.host_address == "10.220.0.5"
    assert plan.namespace_address == "10.220.0.6"
    assert plan.client_ip_allowlist == ("198.51.100.7/32",)
    command = killswitch_apply_command(plan)
    assert command.arguments == (
        "lxvpn-2",
        "2",
        "9",
        "8.8.8.8",
        "443",
        "tcp",
        "21002",
        "nftables",
        "198.51.100.7/32",
    )


def test_nft_rules_are_connection_scoped_and_fail_closed() -> None:
    plan = _plan()
    from app.services.network.firewall_rules import FirewallRuleSpec

    spec = FirewallRuleSpec(
        connection_id=plan.connection_id,
        namespace=plan.namespace,
        host_veth=plan.host_veth,
        namespace_veth=plan.namespace_veth,
        host_address=plan.host_address,
        namespace_address=plan.namespace_address,
        remote_address=plan.remote_address,
        remote_port=plan.remote_port,
        remote_protocol=plan.remote_protocol,
        socks_port=plan.socks_port,
        client_ip_allowlist=plan.client_ip_allowlist,
    )

    rules = nft_rule_set(spec)

    assert rules.namespace_table == "vpngate_n2"
    assert rules.host_table == "vpngate_h2"
    assert "policy drop" in rules.namespace_script
    assert 'oifname "tun0" accept' in rules.namespace_script
    assert 'oifname "lvn2" ip daddr 8.8.8.8 udp dport 1194 accept' in rules.namespace_script
    assert "198.51.100.7/32 tcp dport 21002 dnat ip to 10.220.0.6:21002" in rules.host_script
    assert "tcp dport 21002 drop" in rules.host_script
    assert "snat ip to 10.220.0.5" in rules.host_script
    assert (
        "ip saddr 10.220.0.6 ip daddr 8.8.8.8 udp dport 1194 masquerade"
        in rules.host_script
    )
    assert (
        'iifname "lvh2" ip saddr 10.220.0.6 ip daddr 8.8.8.8'
        in rules.host_script
    )
    assert "flush ruleset" not in rules.namespace_script + rules.host_script


def test_iptables_fallback_uses_only_connection_owned_chains() -> None:
    plan = _plan()
    from app.services.network.firewall_rules import FirewallRuleSpec

    spec = FirewallRuleSpec(
        connection_id=plan.connection_id,
        namespace=plan.namespace,
        host_veth=plan.host_veth,
        namespace_veth=plan.namespace_veth,
        host_address=plan.host_address,
        namespace_address=plan.namespace_address,
        remote_address=plan.remote_address,
        remote_port=plan.remote_port,
        remote_protocol=plan.remote_protocol,
        socks_port=plan.socks_port,
        client_ip_allowlist=plan.client_ip_allowlist,
    )

    rules = iptables_rule_set(spec)
    flattened = rules.namespace_apply + rules.host_apply + rules.namespace_cleanup + rules.host_cleanup

    assert rules.namespace_chains == ("VGO2", "VGI2")
    assert rules.host_chains == ("VGP2", "VGS2", "VGF2", "VGD2")
    assert all(arguments not in {("-F",), ("-t", "nat", "-F")} for arguments in flattened)
    assert any("DNAT" in arguments for arguments in rules.host_apply)
    assert any("SNAT" in arguments for arguments in rules.host_apply)
    assert any("MASQUERADE" in arguments for arguments in rules.host_apply)
    assert any(
        arguments[:4] == ("-A", "VGF2", "-i", "lvh2")
        and "8.8.8.8" in arguments
        for arguments in rules.host_apply
    )


def test_scan_only_rules_omit_public_socks_mapping() -> None:
    from app.services.network.firewall_rules import FirewallRuleSpec

    plan = build_killswitch_plan(
        3,
        node_id=9,
        remote_address="8.8.8.8",
        remote_port=1194,
        remote_protocol="udp",
        socks_port=None,
    )
    command = killswitch_apply_command(plan)
    spec = FirewallRuleSpec(
        connection_id=plan.connection_id,
        namespace=plan.namespace,
        host_veth=plan.host_veth,
        namespace_veth=plan.namespace_veth,
        host_address=plan.host_address,
        namespace_address=plan.namespace_address,
        remote_address=plan.remote_address,
        remote_port=plan.remote_port,
        remote_protocol=plan.remote_protocol,
        socks_port=None,
        client_ip_allowlist=(),
    )

    nft = nft_rule_set(spec)
    iptables = iptables_rule_set(spec)

    assert command.arguments[6] == "-"
    assert "dnat" not in nft.host_script
    assert "tcp dport" not in nft.namespace_script
    assert "masquerade" in nft.host_script
    assert not any("DNAT" in arguments for arguments in iptables.host_apply)
    assert not any("SNAT" in arguments for arguments in iptables.host_apply)
    assert any("MASQUERADE" in arguments for arguments in iptables.host_apply)


def test_manager_applies_and_verifies_backend() -> None:
    executor = FirewallExecutor()
    manager = KillSwitchManager(executor)

    runtime = manager.apply(_plan())

    assert runtime.active is True
    assert runtime.backend == "nftables"
    assert [command.operation for command in executor.commands] == [
        NetworkOperation.KILLSWITCH_APPLY,
        NetworkOperation.KILLSWITCH_STATUS,
    ]


def test_apply_failure_rolls_back_only_connection_rules() -> None:
    executor = FirewallExecutor(apply_code=1)
    manager = KillSwitchManager(executor)

    with pytest.raises(KillSwitchOperationError, match="killswitch_apply_failed"):
        manager.apply(_plan())

    assert executor.commands[-1].operation is NetworkOperation.KILLSWITCH_REMOVE


def test_inactive_verification_removes_partial_rules() -> None:
    executor = FirewallExecutor(status_code=3)
    manager = KillSwitchManager(executor)

    with pytest.raises(KillSwitchOperationError, match="killswitch_verify_failed"):
        manager.apply(_plan())

    assert executor.commands[-1].operation is NetworkOperation.KILLSWITCH_REMOVE


def test_success_status_requires_a_known_backend() -> None:
    executor = FirewallExecutor(backend="unexpected")
    manager = KillSwitchManager(executor)

    with pytest.raises(KillSwitchOperationError, match="killswitch_status_failed"):
        manager.status(_plan())


def test_real_executor_requires_separate_firewall_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")
    executor = RealNetworkExecutor(
        enabled=True,
        sudo_path="/usr/bin/sudo",
        helper_path="/usr/local/libexec/vpngate-manager-helper",
    )
    manager = KillSwitchManager(executor, allow_real_firewall=False)

    with pytest.raises(KillSwitchOperationError, match="VPNGATE_ENABLE_REAL_FIREWALL"):
        manager.status(_plan())
