import configparser
import ipaddress
import json
import sys
from collections.abc import Callable, Generator, Iterable
from contextlib import suppress
from functools import partial
from io import TextIOWrapper
from pathlib import Path
from typing import Literal, Sequence
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

from termcolor import colored as C


def upd_or_create_wireguard_conf(
    source_ips: list[str], route_rule: str, conf_path: Path | str, output_path: Path | str | None = None
) -> None:
    config = configparser.ConfigParser(strict=False)
    config.optionxform = str  # preserve case
    config.read(conf_path, encoding="utf-8")

    if "Interface" not in config:
        sys.exit("The .conf file does not contain a section [Interface]")

    if "Peer" not in config:
        sys.exit("The .conf file does not contain a section [Peer]")

    config["Peer"]["AllowedIPs"] = ", ".join(source_ips)
    # TODO(Ars): Сделать поддержку адресов для игнора
    config["Peer"]["DisallowedIPs"]

    match route_rule:
        case "1":
            pass
            # Amnezia Obfuscate Settings
            # config["Interface"]["Jc"] = "12"
            # config["Interface"]["Jmin"] = "49"
            # config["Interface"]["Jmax"] = "850"
            # config["Interface"]["S1"] = "57"
            # config["Interface"]["S2"] = "146"
            # config["Interface"]["H1"] = "1013348378"
            # config["Interface"]["H2"] = "251178477"
            # config["Interface"]["H3"] = "1212663547"
            # config["Interface"]["H4"] = "1619497452"
        case "2":
            # WireSock Obfuscate Settings
            config["Interface"]["ObfuscateKey"] = "12345678901234567890123456789012"
            config["Interface"]["ObfuscateMethod"] = "xor"

    with open(output_path or conf_path, "w", encoding="utf-8") as f:
        config.write(f)


def input_program(msg: str, expected_programs: Iterable[str]) -> str:
    while True:
        selected_program = input(C(msg, "light_cyan"))

        if selected_program not in expected_programs:
            colored_expected_programs = C(f"{expected_programs}", attrs=["underline"])
            print(
                C(
                    f"An invalid program has been selected. Programs are allowed: {colored_expected_programs}",
                    "red",
                )
            )
            continue

        return selected_program


def input_filepath(file_format: str, stop_word: bool = False) -> Path | None:
    if stop_word:
        input_msg = (
            "Enter N to exit selecting files or "
            f"Enter the path to the file with the ip addresses in {file_format} format: "
        )
    else:
        input_msg = f"Enter the path to the file with the ip addresses in {file_format} format: "

    while True:
        filename = input(C(input_msg, "light_cyan"))

        if not filename:
            print(C("The path to the file with ip addresses cannot be empty.", "red"))
            continue

        if stop_word and filename.lower() == "n":
            return None

        filepath = Path(filename)

        if not filepath.is_file():
            colored_filename = C(filename, attrs=["underline"])
            print(C(f"There is no such file with ip addresses: {colored_filename}", "red"))
            continue

        return filepath


def input_filepath2(msg: str, ext: str | None = None, check: bool = True) -> Path:
    while True:
        filename = input(C(msg, "light_cyan"))

        if not filename:
            print(C("The name of the file cannot be empty.", "red"))
            continue

        if ext and (not filename.endswith(ext) or len(filename) < len(ext) + 1):
            colored_expected_ext = C(f"{ext}", attrs=["underline"])
            print(C(f"The name of the file must have an extension {colored_expected_ext}", "red"))
            continue

        filepath = Path(filename)

        if check and not filepath.is_file():
            colored_filename = C(filename, attrs=["underline"])
            print(C(f"There is no such file: {colored_filename}", "red"))
            continue

        return filepath


def get_filename(entering_filename_func: Callable) -> str:
    while True:
        filepath: Path = entering_filename_func()

        if filepath.is_file():
            selected_program = input_program(
                C(
                    "Such a file already exists.\n"
                    "Select a program:\n"
                    "0 - if you want to enter another name.\n"
                    "1 - if you want to overwrite an existing file.\n",
                    "light_cyan",
                ),
                ("0", "1"),
            )
            if selected_program == "0":
                continue
        return filepath


class ExceedingInvalidAddressLimitError(Exception):
    pass


class IPValidator:
    comment_prefixes: Sequence[str] = ("#", ";", "//")

    def __init__(self, max_invalid: int = 30) -> None:
        self.max_invalid = max_invalid
        self.invalid_count = 0

    def is_valid(self, value: str) -> bool:
        if value.startswith(self.comment_prefixes):
            print(C(f"Duplicate address found, it will be skipped: {value}", "yellow"))
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


def amnezia_file_reader(ips_file: TextIOWrapper) -> Generator[str, None, None]:
    try:
        deserialized_ips = json.load(ips_file)
    except json.JSONDecodeError as exc:
        sys.exit(f"Invalid selected file format. Exiting the program. Exception: {type(exc).__name__}")
    else:
        for obj in deserialized_ips:
            yield obj.get("hostname")


def plaintext_file_reader(ips_file: TextIOWrapper) -> Generator[str, None, None]:
    yield from ips_file


def read_ips_file(
    source_ips_filenames: list[Path], reader: Callable[[TextIOWrapper], Generator[str, None, None]]
) -> list[str]:
    ips_list = []
    ip_validator = IPValidator()

    for source_ips_filename in source_ips_filenames:
        with open(source_ips_filename, encoding="utf-8") as ips_file:
            for ip in reader(ips_file):
                cleaned_ip = ip.strip()

                if cleaned_ip:
                    try:
                        if not ip_validator.is_valid(cleaned_ip):
                            continue
                    except ExceedingInvalidAddressLimitError as exc:
                        sys.exit(
                            f"Failed address limit. Exiting the program. Exception: {type(exc).__name__}"
                        )

                    if cleaned_ip not in ips_list:
                        ips_list.append(cleaned_ip)
                    else:
                        print(C(f"Duplicate address found, it will be skipped: {cleaned_ip}", "yellow"))
                else:
                    print(C("Empty address found, it will be skipped", "yellow"))

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
            print(C(f"Invalid vless configuration link passed. Exception: {type(exc).__name__}", "red"))
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


def write_json_file(filename: Path | str, data: dict | list[dict]) -> None:
    with open(filename, "w+", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
        file.write("\n")


def entering_amnezia_ips_file() -> Path:
    while True:
        source_ips_filename = input_filepath("amnezia")
        if not source_ips_filename.name.endswith(".json") or len(source_ips_filename.name) < 6:
            print(C("The name of the ips file must have an extension .json", "red"))
            continue

        return source_ips_filename


def plaintext_to_amnezia_format(ips_list: list[str]) -> list[dict[str, str]]:
    return [{"hostname": ip, "ip": ""} for ip in ips_list]


def write_ips_file(filename: Path | str, ips: dict) -> None:
    with open(filename, "w+", encoding="utf-8") as file:
        for ip in ips:
            file.write(f"{ip}\n")


def input_ips_files(_format: str) -> list[Path]:
    source_ips_filenames = []
    while True:
        source_ips_filename = input_filepath(_format, stop_word=True)

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

    plaintext_ips_filename = get_filename(
        partial(input_filepath2, msg="Enter a name for the new plaintext file: ", check=False)
    )

    ips_list = read_ips_file([source_ips_filename], reader=amnezia_file_reader)
    write_ips_file(plaintext_ips_filename, ips_list)

    print(C("The file with ip addresses in plaintext format has been successfully created.", "green"))


def run_program_2() -> None:
    source_ips_filename = input_filepath("plaintext")

    amnezia_ips_filename = get_filename(
        partial(
            input_filepath2, msg="Enter a name for the new amnezia json file: ", ext=".json", check=False
        )
    )

    ips_list = read_ips_file([source_ips_filename], reader=plaintext_file_reader)
    ips_list = plaintext_to_amnezia_format(ips_list)
    write_json_file(amnezia_ips_filename, ips_list)

    print(C("The file with ip addresses in amnezia json format has been successfully created.", "green"))


def run_program_3() -> None:
    message = (
        "Select a program:\n"
        "1 - Combine files in the plaintext format.\n"
        "2 - Combine files in the amnezia format.\n"
    )
    route_rule = input_program(message, ("1", "2"))

    if route_rule == "1":
        source_ips_filenames = input_ips_files("plaintext")

        print(
            C(
                f"Selected ip address files: {[str(filepath) for filepath in source_ips_filenames]}",
                "green",
            )
        )

        source_ips = read_ips_file(source_ips_filenames, reader=plaintext_file_reader)

        new_filename = get_filename(
            partial(input_filepath2, msg="Enter a name for the new ips file: ", check=False)
        )

        write_ips_file(new_filename, source_ips)

    elif route_rule == "2":
        source_ips_filenames = input_ips_files("amnezia")

        print(
            C(
                f"Selected ip address files: {[str(filepath) for filepath in source_ips_filenames]}",
                "green",
            )
        )

        source_ips = read_ips_file(source_ips_filenames, reader=amnezia_file_reader)

        source_ips = [{"hostname": ip, "ip": ""} for ip in source_ips]

        new_filename = get_filename(
            partial(input_filepath2, msg="Enter a name for the new ips file: ", ext=".json", check=False)
        )

        write_json_file(new_filename, source_ips)

    print(C("The file with ip addresses has been successfully created.", "green"))


def run_program_4() -> None:
    message = (
        "Select a program:\n"
        "1 - Create a file for proxying the specified ip addresses.\n"
        "2 - Create a file for proxying all ip addresses.\n"
    )
    route_rule = input_program(message, ("1", "2"))

    if route_rule == "2":
        source_ips = ["0.0.0.0/0", "::/0"]

    elif route_rule == "1":
        source_ips_filenames = input_ips_files("plaintext")

        print(
            C(
                f"Selected ip address files: {[str(filepath) for filepath in source_ips_filenames]}",
                "green",
            )
        )

        source_ips = read_ips_file(source_ips_filenames, reader=plaintext_file_reader)

    message = "Select a your vpn client:\n1 - Amnezia\n2 - WireSock\n3 - Other clients\n"
    route_rule = input_program(message, ("1", "2", "3"))

    config_filename = input_filepath2(
        msg="Enter a name for the existing configuration file for copying: ", ext=".conf"
    )

    new_config_filename = get_filename(
        partial(
            input_filepath2,
            msg="Enter a name for the new configuration file: ",
            ext=".conf",
            check=False,
        )
    )

    upd_or_create_wireguard_conf(source_ips, route_rule, config_filename, new_config_filename)

    print(C("The configuration file has been created successfully.", "green"))


def run_program_5() -> None:
    source_ips_filenames = input_ips_files("plaintext")

    print(
        C(
            f"Selected ip address files: {[str(filepath) for filepath in source_ips_filenames]}",
            "green",
        )
    )

    message = (
        "Select a program:\n"
        "1 - Create a file for proxying the specified ip addresses.\n"
        "(selected ips -> outbound 'proxy', other ips -> outbound 'direct').\n"
        "2 - Create a file for NOT proxying the specified ip addresses.\n"
        "(selected ips -> outbound 'direct', other ips -> outbound 'proxy').\n"
    )
    route_rule = input_program(message, ("1", "2"))

    config_filename = get_filename(
        partial(
            input_filepath2,
            msg="Enter a name for the new nekobox configuration file: ",
            ext=".json",
            check=False,
        )
    )

    source_ips = read_ips_file(source_ips_filenames, reader=plaintext_file_reader)
    vless_config, vless_config_params = entering_vless_uri_config()
    config_template = fill_config_template(vless_config, vless_config_params, source_ips, route_rule)
    write_json_file(config_filename, config_template)

    print(C("The configuration file has been created successfully.", "green"))


def main() -> None:
    print(
        C(
            "Greetings, this program was created by the author: 'https://github.com/Friskes'\n"
            "to simplify the creation of configurations for vpn clients.\n"
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

    selected_program = input_program(message, ("1", "2", "3", "4", "5"))
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
