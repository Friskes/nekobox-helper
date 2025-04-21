import configparser
import ipaddress
import json
import sys
from collections.abc import Callable, Iterable
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Literal
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

from termcolor import colored as C


def update_or_create_conf(
    source_ips: list[str], route_rule: str, conf_path: Path | str, output_path: Path | str | None = None
) -> None:
    config = configparser.ConfigParser(strict=False)
    config.optionxform = str  # preserve case
    config.read(conf_path, encoding="utf-8")

    if "Interface" not in config:
        raise ValueError("The .conf file does not contain a section [Interface]")
    if "Peer" not in config:
        raise ValueError("The .conf file does not contain a section [Peer]")

    config["Peer"]["AllowedIPs"] = ", ".join(source_ips)

    match route_rule:
        case "1":
            # Amnezia Obfuscate Settings
            config["Interface"]["Jc"] = "12"
            config["Interface"]["Jmin"] = "49"
            config["Interface"]["Jmax"] = "850"
            config["Interface"]["S1"] = "57"
            config["Interface"]["S2"] = "146"
            config["Interface"]["H1"] = "1013348378"
            config["Interface"]["H2"] = "251178477"
            config["Interface"]["H3"] = "1212663547"
            config["Interface"]["H4"] = "1619497452"
        case "2":
            # WireSock Obfuscate Settings
            config["Interface"]["ObfuscateKey"] = "12345678901234567890123456789012"
            config["Interface"]["ObfuscateMethod"] = "xor"

    with open(output_path or conf_path, "w", encoding="utf-8") as f:
        config.write(f)


def entering_numeric_choice(message: str, expected_programs: Iterable[str]) -> str:
    while True:
        selected_program = input(C(message, "light_cyan"))
        if selected_program not in expected_programs:
            print(
                C(
                    f"An invalid program has been selected. Programs are allowed: {expected_programs}",
                    "red",
                )
            )
            continue

        return selected_program


def entering_ips_file(_format: str, stop_word: bool = False) -> Path | None:
    input_msg = f"Enter the path to the file with the ip addresses in {_format} format: "
    if stop_word:
        input_msg = (
            "Enter N to exit selecting files or "
            f"Enter the path to the file with the ip addresses in {_format} format: "
        )

    while True:
        source_ips_filename = input(C(input_msg, "light_cyan"))
        if not source_ips_filename:
            print(C("The path to the file with ip addresses cannot be empty.", "red"))
            continue

        if stop_word and source_ips_filename.lower() == "n":
            return None

        source_ips_filename = Path(source_ips_filename)
        if not source_ips_filename.is_file():
            print(C("There is no such file with ip addresses.", "red"))
            continue

        return source_ips_filename


def entering_filename(msg: str, ext: str | None = None) -> Path:
    while True:
        config_filename = input(C(msg, "light_cyan"))

        if not config_filename:
            print(C("The name of the file cannot be empty.", "red"))
            continue

        if ext and (not config_filename.endswith(ext) or len(config_filename) < len(ext) + 1):
            print(C(f"The name of the file must have an extension {ext}", "red"))
            continue

        return Path(config_filename)


def choosing_option(filename: Path) -> bool:
    if not filename.is_file():
        return True

    while True:
        decision = input(
            C(
                "Such a file already exists. "
                "Enter: Y if you want to overwrite an existing file. "
                "Or enter: N to enter another name. ",
                "light_cyan",
            )
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
        if value.startswith("#"):
            return False

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

            print(C(f"Invalid address found, it will be skipped {value}", "red"))
            return False
        else:
            self.invalid_count = 0
            return True


def read_ips_file(source_ips_filenames: list[Path]) -> list[str]:
    ips_list = []
    ip_validator = IPValidator()

    for source_ips_filename in source_ips_filenames:
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

                    if cleaned_line not in ips_list:
                        ips_list.append(cleaned_line)
                    else:
                        print(C(f"Duplicate address found, it will be skipped {cleaned_line}", "yellow"))

    if not ips_list:
        sys.exit("A file with ip addresses cannot be empty. Exiting the program.")

    return ips_list


def entering_vless_uri_config() -> tuple[ParseResult, dict[str, str]]:
    expected_vless_config_params = {"flow", "security", "pbk", "sid", "sni", "fp"}

    while True:
        vless_uri_config = input(C("Enter the vless configuration link: ", "light_cyan"))

        if not vless_uri_config:
            print(C("The vless configuration link cannot be empty.", "red"))
            continue

        if not vless_uri_config.startswith("vless://"):
            print(C("The vless configuration link is invalid.", "red"))
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
                print(C(f"The vless configuration link is invalid. {uri_values}", "red"))
                continue

            vless_config_params = {k: unquote(v[0]) for k, v in parse_qs(vless_config.query).items()}

            missing_config_params = expected_vless_config_params - set(vless_config_params.keys())
            if missing_config_params:
                print(
                    C(
                        "The vless configuration link is invalid. "
                        f"Missing parameters: {missing_config_params}",
                        "red",
                    )
                )
                if len(missing_config_params) == 1 and "flow" in missing_config_params:
                    print(
                        C(
                            "Missing parameter: flow was created automatically with value: xtls-rprx-vision",
                            "yellow",
                        )
                    )
                    vless_config_params["flow"] = "xtls-rprx-vision"
                else:
                    continue
        except Exception as exc:
            print(C(f"Invalid vless configuration link passed: {exc!s}", "red"))
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
            print(C("The name of the ips file must have an extension .json", "red"))
            continue

        return source_ips_filename


def read_amnezia_ips_file(source_ips_filename: Path) -> list[dict[str, str]]:
    while True:
        with open(source_ips_filename.name, encoding="utf-8") as source_ips_file:
            ips_list = json.load(source_ips_file)

        if not ips_list:
            print(C("A file with ip addresses cannot be empty.", "red"))
            continue

        return ips_list


def amnezia_to_plaintext_format(ips_list: list[dict[str, str]]) -> list[str]:
    plaintext_ips_list = []

    for row in ips_list:
        hostname = row.get("hostname")

        if hostname:
            if hostname not in plaintext_ips_list:
                plaintext_ips_list.append(hostname)
            else:
                print(C(f"The 'hostname' already exists, it will be skipped: {hostname}", "yellow"))
        else:
            print(C(f"The 'hostname' field is missing in the record: {row}", "yellow"))

    return plaintext_ips_list


def plaintext_to_amnezia_format(ips_list: list[str]) -> list[dict[str, str]]:
    return [{"hostname": ip, "ip": ""} for ip in ips_list]


def write_ips_file(filename: str, ips: dict) -> None:
    with open(filename, "w+", encoding="utf-8") as file:
        for ip in ips:
            file.write(f"{ip}\n")


def entering_ips_files(_format: str) -> list[Path]:
    source_ips_filenames = []
    while True:
        source_ips_filename = entering_ips_file(_format, stop_word=True)

        if source_ips_filename is None:
            if source_ips_filenames:
                return source_ips_filenames
            continue

        if source_ips_filename in source_ips_filenames:
            print(C("Such a file has already been selected.", "red"))
            continue

        source_ips_filenames.append(source_ips_filename)


def run_program_1() -> None:
    source_ips_filename = entering_amnezia_ips_file()

    entering_filename_func = partial(entering_filename, msg="Enter a name for the plaintext file: ")
    plaintext_ips_filename = get_filename(entering_filename_func)

    ips_list = read_amnezia_ips_file(source_ips_filename)
    ips_list = amnezia_to_plaintext_format(ips_list)
    write_ips_file(plaintext_ips_filename, ips_list)

    print(C("The file with ip addresses in plaintext format has been successfully created.", "green"))


def run_program_2() -> None:
    source_ips_filename = entering_ips_file("plaintext")

    entering_filename_func = partial(
        entering_filename, msg="Enter a name for the amnezia json file: ", ext=".json"
    )
    amnezia_ips_filename = get_filename(entering_filename_func)

    ips_list = read_ips_file([source_ips_filename])
    ips_list = plaintext_to_amnezia_format(ips_list)
    write_ips_file(amnezia_ips_filename, ips_list)

    print(C("The file with ip addresses in amnezia json format has been successfully created.", "green"))


def run_program_3() -> None:
    message = (
        "Select a program:\n"
        "1 - Combine files in the plaintext format.\n"
        "2 - Combine files in the amnezia format.\n"
    )
    route_rule = entering_numeric_choice(message, ("1", "2"))

    if route_rule == "1":
        source_ips_filenames = entering_ips_files("plaintext")

        print(
            C(
                f"Selected ip address files: {[source_ip.name for source_ip in source_ips_filenames]}",
                "green",
            )
        )

        source_ips = read_ips_file(source_ips_filenames)

        entering_filename_func = partial(entering_filename, msg="Enter a name for the new ips file: ")
        new_filename = get_filename(entering_filename_func)

        write_ips_file(new_filename, source_ips)

    elif route_rule == "2":
        source_ips_filenames = entering_ips_files("amnezia")

        print(
            C(
                f"Selected ip address files: {[source_ip.name for source_ip in source_ips_filenames]}",
                "green",
            )
        )

        source_ips: list[dict[str, str]] = []
        for source_ips_filename in source_ips_filenames:
            ips_list = read_amnezia_ips_file(source_ips_filename)
            source_ips.extend(ips_list)

        ips = []
        tmp_ips = []
        for ip in source_ips:
            hostname = ip.get("hostname")
            if hostname and hostname not in tmp_ips:
                ips.append(ip)
                tmp_ips.append(hostname)

        entering_filename_func = partial(
            entering_filename, msg="Enter a name for the new ips file: ", ext=".json"
        )
        new_filename = get_filename(entering_filename_func)

        write_config_file(new_filename, ips)

    print(C("The file with ip addresses has been successfully created.", "green"))


def run_program_4() -> None:
    message = (
        "Select a program:\n"
        "1 - Create a file for proxying the specified ip addresses.\n"
        "2 - Create a file for proxying all ip addresses.\n"
    )
    route_rule = entering_numeric_choice(message, ("1", "2"))

    if route_rule == "2":
        source_ips = ["0.0.0.0/0", "::/0"]
        route_rule = "3"

    elif route_rule == "1":
        source_ips_filenames = entering_ips_files("plaintext")

        print(
            C(
                f"Selected ip address files: {[source_ip.name for source_ip in source_ips_filenames]}",
                "green",
            )
        )

        source_ips = read_ips_file(source_ips_filenames)

        message = "Select a your vpn client:\n1 - Amnezia\n2 - WireSock\n3 - Other clients\n"
        route_rule = entering_numeric_choice(message, ("1", "2", "3"))

    config_filename = entering_filename(
        msg="Enter a name for the existing configuration file: ", ext=".conf"
    )

    entering_filename_func = partial(
        entering_filename, msg="Enter a name for the new configuration file: ", ext=".conf"
    )
    new_config_filename = get_filename(entering_filename_func)

    update_or_create_conf(source_ips, route_rule, config_filename, new_config_filename)

    print(C("The configuration file has been created successfully.", "green"))


def run_program_5() -> None:
    source_ips_filename = entering_ips_file("plaintext")

    message = (
        "Select a program:\n"
        "1 - Create a file for proxying the specified ip addresses.\n"
        "(selected ips -> outbound 'proxy', other ips -> outbound 'direct').\n"
        "2 - Create a file for NOT proxying the specified ip addresses.\n"
        "(selected ips -> outbound 'direct', other ips -> outbound 'proxy').\n"
    )
    route_rule = entering_numeric_choice(message, ("1", "2"))

    entering_filename_func = partial(
        entering_filename, msg="Enter a name for the new nekobox configuration file: ", ext=".json"
    )
    config_filename = get_filename(entering_filename_func)

    ips_list = read_ips_file([source_ips_filename])
    vless_config, vless_config_params = entering_vless_uri_config()
    config_template = fill_config_template(vless_config, vless_config_params, ips_list, route_rule)
    write_config_file(config_filename, config_template)

    print(C("The configuration file has been created successfully.", "green"))


def main() -> None:
    program_version = "v0.1.0"

    print(
        C(
            "Greetings, this program was created by the author: 'https://github.com/Friskes'\n"
            "to simplify the creation of configurations for vpn clients.\n"
            f"{program_version}\n",
            "light_magenta",
        )
    )

    message = (
        "Select a program:\n"
        "1 - Convert a file with ip addresses from the amnezia json format to the plaintext format.\n"
        "2 - Convert a file with ip addresses from the plaintext format to the amnezia json format.\n"
        "3 - Combine files in the same format with ip addresses into a single file.\n"
        "4 - Create a Amnezia/WireSock configuration file for separate tunneling for wireguard protocol.\n"
        "5 - Create a nekobox android configuration file for separate tunneling for vless protocol.\n"
    )

    selected_program = entering_numeric_choice(message, ("1", "2", "3", "4", "5"))
    match selected_program:
        case "1":
            run_program_1()
        case "2":
            run_program_2()
        case "3":
            run_program_3()
        case "4":
            run_program_4()
        case "5":
            run_program_5()

    input(C("Press enter to close the program...", "light_cyan"))


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
