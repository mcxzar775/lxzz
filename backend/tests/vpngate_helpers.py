import base64
import csv
import io


CSV_COLUMNS = [
    "HostName",
    "IP",
    "Score",
    "Ping",
    "Speed",
    "CountryLong",
    "CountryShort",
    "NumVpnSessions",
    "Uptime",
    "TotalUsers",
    "TotalTraffic",
    "LogType",
    "Operator",
    "Message",
    "OpenVPN_ConfigData_Base64",
]


def make_openvpn_config(
    ip_address: str = "8.8.8.8",
    *,
    protocol: str = "udp",
    port: int = 1194,
    extra_directive: str | None = None,
) -> bytes:
    extra = f"{extra_directive}\n" if extra_directive else ""
    return (
        "client\n"
        "dev tun\n"
        f"proto {protocol}\n"
        f"remote {ip_address} {port}\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "cipher AES-128-CBC\n"
        "auth SHA1\n"
        "verb 2\n"
        f"{extra}"
        "<ca>\n"
        "-----BEGIN CERTIFICATE-----\n"
        "VEVTVA==\n"
        "-----END CERTIFICATE-----\n"
        "</ca>\n"
    ).encode("utf-8")


def make_csv_row(
    config: bytes,
    *,
    ip_address: str = "8.8.8.8",
    host_name: str = "public-vpn-1",
    country_code: str = "US",
    score: str = "1000",
) -> list[str]:
    return [
        host_name,
        ip_address,
        score,
        "42",
        "1000000",
        "United States",
        country_code,
        "5",
        "3600000",
        "200",
        "987654321",
        "",
        "",
        "",
        base64.b64encode(config).decode("ascii"),
    ]


def make_vpngate_csv(rows: list[list[str]]) -> bytes:
    output = io.StringIO(newline="")
    output.write("#" + ",".join(CSV_COLUMNS) + "\n")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    output.write("*\n")
    return output.getvalue().encode("utf-8")
