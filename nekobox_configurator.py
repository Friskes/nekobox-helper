import ipaddress
import json
import sys
from collections.abc import Callable
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Literal
from urllib.parse import ParseResult, parse_qs, unquote, urlparse


def entering_numeric_choice(message: str) -> str:
    expected_programs = ("1", "2")

    while True:
        selected_program = input(message)
        if selected_program not in expected_programs:
            print(f"An invalid program has been selected. Programs are allowed: {expected_programs}")
            continue

        return selected_program


def entering_ips_file(_format: str) -> Path:
    while True:
        source_ips_filename = input(
            f"Enter the path to the file with the ip addresses in {_format} format: "
        )
        if not source_ips_filename:
            print("The path to the file with ip addresses cannot be empty.")
            continue

        source_ips_filename = Path(source_ips_filename)
        if not source_ips_filename.is_file():
            print("There is no such file with ip addresses.")
            continue

        return source_ips_filename


def entering_filename(message: str) -> Path:
    while True:
        config_filename = input(message)
        if not config_filename or not config_filename.endswith(".json") or len(config_filename) < 6:
            print("The name of the file cannot be empty and must have an extension .json")
            continue

        return Path(config_filename)


def entering_nekobox_filename(message: str) -> Path:
    while True:
        config_filename = input(message)
        if not config_filename:
            print("The name of the file cannot be empty.")
            continue

        return Path(config_filename)


def choosing_option(filename: Path) -> bool:
    if not filename.is_file():
        return True

    while True:
        decision = input(
            "Such a file already exists. "
            "Enter: Y if you want to overwrite an existing file. "
            "Or enter: N to enter another name. "
        )
        lowered_decision = decision.lower()

        if lowered_decision == "y":
            return True

        elif lowered_decision == "n":
            return False


def get_filename(entering_filename_func: Callable) -> str:
    filename_ok = False

    while not filename_ok:
        filename = entering_filename_func()
        filename_ok = choosing_option(filename)

    return filename


class ExceedingInvalidAddressLimitError(Exception):
    pass


class IPValidator:
    def __init__(self, max_invalid: int = 30) -> None:
        self.max_invalid = max_invalid
        self.invalid_count = 0

    def validate(self, value: str) -> bool:
        try:
            if "/" in value:
                ipaddress.IPv4Network(value, strict=False)
            else:
                ipaddress.IPv4Address(value)
        except ValueError as exc:
            self.invalid_count += 1

            if self.invalid_count >= self.max_invalid:
                raise ExceedingInvalidAddressLimitError(
                    f"Exceeded {self.max_invalid} invalid IP addresses in a row."
                ) from exc

            print(f"Invalid address found, it will be skipped {value}")
            return False
        else:
            self.invalid_count = 0
            return True


def read_ips_file(source_ips_filename: Path) -> list[str]:
    ips_list = []
    ip_validator = IPValidator()

    with open(source_ips_filename.name, encoding="utf-8") as source_ips_file:
        #
        for line in source_ips_file:
            cleaned_line = line.strip()

            if cleaned_line:
                try:
                    if not ip_validator.validate(cleaned_line):
                        continue
                except ExceedingInvalidAddressLimitError as exc:
                    sys.exit(f"{exc!s} Exiting the program.")

                ips_list.append(cleaned_line)

    if not ips_list:
        sys.exit("A file with ip addresses cannot be empty. Exiting the program.")

    return ips_list


def entering_vless_uri_config() -> tuple[ParseResult, dict[str, str]]:
    expected_vless_config_params = {"flow", "security", "pbk", "sid", "sni", "fp"}

    while True:
        vless_uri_config = input("Enter the vless configuration link: ")

        if not vless_uri_config:
            print("The vless configuration link cannot be empty.")
            continue

        if not vless_uri_config.startswith("vless://"):
            print("The vless configuration link is invalid.")
            continue

        try:
            vless_config = urlparse(vless_uri_config)
            uri_values = (
                vless_config.hostname,
                vless_config.port,
                vless_config.username,
                vless_config.scheme,
            )

            if not all(uri_values):
                print(f"The vless configuration link is invalid. {uri_values}")
                continue

            vless_config_params = {k: unquote(v[0]) for k, v in parse_qs(vless_config.query).items()}

            missing_config_params = expected_vless_config_params - set(vless_config_params.keys())
            if missing_config_params:
                print(
                    "The vless configuration link is invalid. "
                    f"Missing parameters: {missing_config_params}"
                )
                if len(missing_config_params) == 1 and "flow" in missing_config_params:
                    print(
                        "Missing parameter: flow was created automatically with value: xtls-rprx-vision"
                    )
                    vless_config_params["flow"] = "xtls-rprx-vision"
                else:
                    continue
        except Exception as exc:
            print("Invalid vless configuration link passed:", str(exc))
            continue
        else:
            return vless_config, vless_config_params


def fill_config_template(
    vless_config: ParseResult,
    vless_config_params: dict[str, str],
    ips_list: list[str],
    route_rule: Literal["1", "2"],
) -> dict:
    if route_rule == "1":
        ips_list_outbound_rule = "proxy"
        other_ips_outbound_rule = "direct"

    elif route_rule == "2":
        ips_list_outbound_rule = "direct"
        other_ips_outbound_rule = "proxy"

    return {
        "dns": {
            "independent_cache": True,
            "rules": [
                {"domain": ["dns.google"], "server": "dns-direct"},
                {"outbound": ["any"], "server": "dns-direct"},
            ],
            "servers": [
                {
                    "address": "https://dns.google/dns-query",
                    "address_resolver": "dns-direct",
                    "strategy": "ipv4_only",
                    "tag": "dns-remote",
                },
                {
                    "address": "https://120.53.53.53/dns-query",
                    "address_resolver": "dns-local",
                    "detour": "direct",
                    "strategy": "ipv4_only",
                    "tag": "dns-direct",
                },
                {"address": "local", "detour": "direct", "tag": "dns-local"},
                {"address": "rcode://success", "tag": "dns-block"},
            ],
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "listen_port": 6450,
                "override_address": "8.8.8.8",
                "override_port": 53,
                "tag": "dns-in",
                "type": "direct",
            },
            {
                "domain_strategy": "",
                "endpoint_independent_nat": True,
                "inet4_address": ["172.19.0.1/28"],
                "mtu": 9000,
                "sniff": True,
                "sniff_override_destination": False,
                "stack": "mixed",
                "tag": "tun-in",
                "type": "tun",
            },
            {
                "domain_strategy": "",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": True,
                "sniff_override_destination": False,
                "tag": "mixed-in",
                "type": "mixed",
            },
        ],
        "log": {"level": "panic"},
        "outbounds": [
            {
                "flow": vless_config_params["flow"],
                "packet_encoding": "",
                "server": vless_config.hostname,
                "server_port": vless_config.port,
                "tls": {
                    "enabled": True,
                    "insecure": False,
                    vless_config_params["security"]: {
                        "enabled": True,
                        "public_key": vless_config_params["pbk"],
                        "short_id": vless_config_params["sid"],
                    },
                    "server_name": vless_config_params["sni"],
                    "utls": {"enabled": True, "fingerprint": vless_config_params["fp"]},
                },
                "uuid": vless_config.username,
                "type": vless_config.scheme,
                "domain_strategy": "prefer_ipv4",
                "tag": "proxy",
            },
            {"tag": "direct", "type": "direct"},
            {"tag": "bypass", "type": "direct"},
            {"tag": "block", "type": "block"},
            {"tag": "dns-out", "type": "dns"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rule_set": [],
            "rules": [
                {"outbound": "dns-out", "port": [53]},
                {"inbound": ["dns-in"], "outbound": "dns-out"},
                {
                    "inbound": ["tun-in"],
                    "ip_cidr": ips_list,
                    "outbound": ips_list_outbound_rule,
                    "rule_set": [],
                },
                {"inbound": ["tun-in"], "outbound": other_ips_outbound_rule},
                {
                    "ip_cidr": ["224.0.0.0/3", "ff00::/8"],
                    "outbound": "block",
                    "source_ip_cidr": ["224.0.0.0/3", "ff00::/8"],
                },
            ],
        },
    }


def write_config_file(config_filename: str, config_template: dict) -> None:
    with open(config_filename, "w+", encoding="utf-8") as config_file:
        json.dump(config_template, config_file, indent=2)
        config_file.write("\n")


def entering_amnezia_ips_file() -> Path:
    while True:
        source_ips_filename = entering_ips_file("amnezia")
        if not source_ips_filename.name.endswith(".json") or len(source_ips_filename.name) < 6:
            print("The name of the ips file must have an extension .json")
            continue

        return source_ips_filename


def read_amnezia_ips_file(source_ips_filename: Path) -> list[dict[str, str]]:
    while True:
        with open(source_ips_filename.name, encoding="utf-8") as source_ips_file:
            ips_list = json.load(source_ips_file)

        if not ips_list:
            print("A file with ip addresses cannot be empty.")
            continue

        return ips_list


def amnezia_to_nekobox_format(ips_list: list[dict[str, str]]) -> list[str]:
    # TODO(Ars): Можно сделать фильтрацию по лишним подсетям.
    nekobox_ips_list = []

    for row in ips_list:
        hostname = row.get("hostname")

        if hostname:
            if hostname not in nekobox_ips_list:
                nekobox_ips_list.append(hostname)
            else:
                print(f"The 'hostname' already exists, it will be skipped: {hostname}")
        else:
            print(f"The 'hostname' field is missing in the record: {row}")

    return nekobox_ips_list


def write_nekobox_ips_file(filename: str, ips: dict) -> None:
    with open(filename, "w+", encoding="utf-8") as file:
        for ip in ips:
            file.write(f"{ip}\n")


def run_program_1() -> None:
    source_ips_filename = entering_ips_file("nekobox")

    message = (
        "Select a program:\n"
        "1 - To proxy only ip addresses from the file with ip addresses, all other traffic is bypassed\n"
        "(selected ips -> outbound 'proxy', other ips -> outbound 'direct').\n"
        "2 - To proxy all traffic, only ip addresses from the file with ip addresses are bypassed\n"
        "(selected ips -> outbound 'direct', other ips -> outbound 'proxy').\n"
    )
    route_rule = entering_numeric_choice(message)

    entering_filename_func = partial(
        entering_filename, message="Enter a name for the new configuration file: "
    )
    config_filename = get_filename(entering_filename_func)

    ips_list = read_ips_file(source_ips_filename)
    vless_config, vless_config_params = entering_vless_uri_config()
    config_template = fill_config_template(vless_config, vless_config_params, ips_list, route_rule)
    write_config_file(config_filename, config_template)

    print("The configuration file has been created successfully.")


def run_program_2() -> None:
    source_ips_filename = entering_amnezia_ips_file()

    entering_filename_func = partial(
        entering_nekobox_filename, message="Enter a name for the nekobox file: "
    )
    nekobox_ips_filename = get_filename(entering_filename_func)

    ips_list = read_amnezia_ips_file(source_ips_filename)
    ips_list = amnezia_to_nekobox_format(ips_list)
    write_nekobox_ips_file(nekobox_ips_filename, ips_list)

    print("The file with ip addresses in nekobox format has been successfully created.")


def main() -> None:
    program_version = "v0.0.3"
    print(
        "Greetings, this program was created by the author: 'https://github.com/Friskes'\n"
        "to simplify interaction with nekobox android client: 'https://github.com/MatsuriDayo/NekoBoxForAndroid'.\n"
        f"{program_version}\n"
    )

    get_ips_link = "https://iplist.opencck.org/"
    message = (
        "Select a program:\n"
        "1 - Create a nekobox android configuration file for separate tunneling for vless protocol.\n"
        "2 - Convert a file with ip addresses from the amnesia format to the nekobox format "
        f"(The file in the amnesia format can be generated by following the link: '{get_ips_link}').\n"
    )

    selected_program = entering_numeric_choice(message)
    match selected_program:
        case "1":
            run_program_1()
        case "2":
            run_program_2()

    input("Press enter to close the program...")


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
