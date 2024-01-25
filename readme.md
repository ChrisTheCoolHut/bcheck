# bcheck

Binary check tool to identify command injection and format string vulnerabilities in blackbox binaries. Using xrefs to commonly injected and format string'd files, it will scan binaries faster than Firmware Slap.

## Install

```
sudo apt install rabbitmq
pip install -e .
```

## Usage
```
bcheck.py -h
usage: bcheck.py [-h] [-p] [-s] [-f] [-t TIMEOUT] [-m MEMORY_LIMIT] [-v] file

positional arguments:
  file                  Binary file to check

optional arguments:
  -h, --help            show this help message and exit
  -p, --printf          Enable printf checking
  -s, --system          Enable command injection checking
  -f, --filter          Enables basic binary filtering
  -v, --verbose         Increases logging verbosity

Worker Options:
  -t TIMEOUT, --timeout TIMEOUT
                        Set worker timeout. Default 60 seconds
  -m MEMORY_LIMIT, --memory_limit MEMORY_LIMIT
                        Set worker memory limit in GB. Default 2GB
```

## Example

```
$ bcheck.py -s examples/upload.cgi
[~] Checking for command injections
100% |############################################################| Elapsed Time: 0:00:01 Time:  0:00:01
Found 5 test sites in binary
[-] Scanned functions:
[-] : 0x401a28 : getLanIP
[+] : 0x4012b8 : mtd_write_firmware
0x7ffefdf8	->	b'/bin/mtd_write -o 0 -l 0 write AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x01 Kernel'
[-] : 0x4009f0 : main
[+] : 0x4010d0 : write_flash_kernel_version
0x7ffefdf8	->	b'nvram_set 2860 old_firmware "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"'
[+] : 0x401338 : mtd_write_bootloader
0x7ffefdf8	->	b'/bin/mtd_write -o 0 -l 0 write AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x01 Bootloader'

```

## Test

```bash
tox
```