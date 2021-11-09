from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_symbol_type, describe_symbol_shndx
from subprocess import check_output

from bin_check.function_models import system_list
import logging

string_cmd = "strings {}"

file_name_blacklist = [
    "cli",
    "busybox",
    "ssi",
    "dns",
    "wpa_",
    "hostapd",
    "lld2d",
    "dhcp",
    "pppd",
    "dropbear",
    "smbd",
    "pppoe",
    "wget",
    "curl",
    "mDNS",
    "sendmail",
    "wifi_",
    "openssl",
    "telnet",
    "libcrypto",
    "snmpd",
    "wlanconfig",
    "ldap",
    "ssh",
    "iwconfig",
]

NETWORK_KEYWORDS = [
    b"Content-Length",
    b"Content-Type",
    b"GET",
    b"HTTP",
    b"HTTP_",
    b"POST",
    b"QUERY_STRING",
    b"REMOTE_ADDR",
    b"boundary=",
    b"http",
    b"http_",
    b"index.",
    b"query",
    b"remote",
    b"soap",
    b"user-agent",
]


def get_symbol_names_elf(filename):

    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        symbols = []

        for section in elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            if section["sh_entsize"] == 0:
                continue

            for _, symbol in enumerate(section.iter_symbols()):
                if (
                    describe_symbol_shndx(symbol["st_shndx"]) != "UND"
                    and describe_symbol_type(symbol["st_info"]["type"]) == "FUNC"
                ):
                    symbols.append(symbol.name)

    return symbols


def get_strings(filename):

    strings = check_output(string_cmd.format(filename), shell=True)
    strings = strings.split(b"\n")

    return strings


def should_check_binary(filename):

    # Filename blacklist
    logging.debug("Filtering blacklisted files")
    for blacklist_filename in file_name_blacklist:
        if blacklist_filename.lower() in filename.lower():
            print("[-] Filter on {}".format(blacklist_filename))
            return False

    # Check symbols
    logging.debug("Filtering binaries without system calls")
    has_function_to_check = False
    symbols = get_symbol_names_elf(filename)
    for symbol in system_list:
        if symbol not in symbols:
            has_function_to_check = True

    if not has_function_to_check:
        return False

    # Check strings
    logging.debug("Filtering by network strings")
    strings = get_strings(filename)
    interesting_strings = False
    for string in strings:
        for keyword in NETWORK_KEYWORDS:
            if keyword in string:
                logging.debug("[+] Found {}".format(string))
                interesting_strings = True

    return interesting_strings
