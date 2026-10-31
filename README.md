tl;dr (kr):

- 인증 서버가 종료되어 정상 초기화가 불가능한 크레마 터치의 인증 절차 우회 코드 (Debian 13, hostapd 지원 무선랜카드 탑재 환경에서 테스트)
- 디펜던시 설치 후 파이썬 코드를 실행하면 자동으로 가상 AP가 설정됨
- 크레마 터치로 해당 AP에 접속하면 인증을 통과함

This code has been implemented in assistance of LLM (GPT-6) on OpenCode. Caveat emptor.

# Crema Touch offline activation hotspot

Revive a **Crema Touch stuck at registration after a factory reset** when its
vendor activation service is unavailable. This tool creates a temporary,
isolated Wi-Fi access point and answers the reader's activation requests locally.
ADB access is not required.

It does **not** flash a ROM, repair hardware or a device that cannot boot, restore
bookstore accounts/DRM licenses, or provide Internet access. It is specific to
the original Crema Touch protocol, **not a universal unbricking tool** for other
Crema models or e-readers.

## Compatibility and requirements

- A Linux computer with **Python 3.9+** and **NetworkManager running** (`nmcli`).
  Windows/macOS and systems using only another network manager are not supported
  by this automatic setup. A VM needs a real, AP-capable Wi-Fi adapter passed
  through to Linux; a normal virtual Ethernet adapter is insufficient.
- A Wi-Fi adapter and Linux driver supporting **2.4 GHz AP mode** via `nl80211`.
  The selected radio cannot simultaneously be your Internet/remote-access link.
  Use Ethernet or another radio if you need to stay connected.
- `hostapd`, `dnsmasq`, `iw`, `ip` (iproute2), `nft` (nftables with inet NAT),
  `nmcli` and OpenSSL with **3DES-CBC** support. No pip packages are needed.
- Administrative access via `sudo` for the running hotspot. The read-only
  `--check` and tests do not need root.
- Physical access to the reader to select Wi-Fi and press registration/continue.

The protocol was inspected in firmware **v2.2.33** and **v2.5.00**. Successful
activation has been reported on a Crema Touch using a Debian 13 host. This is
not validation of every firmware, retailer, Wi-Fi adapter or Linux distribution.
Later startup-handoff improvements have regression tests but need further
hardware coverage.

## 1. Install dependencies

For Debian/Ubuntu-based systems:

```bash
sudo apt install --no-install-recommends python3 openssl hostapd dnsmasq-base iw nftables iproute2 network-manager
```

For other Linux distributions, install the equivalent packages; names differ.
Do not blindly replace your current network manager, especially over a remote
connection: the helper currently requires NetworkManager. Package installation
may itself start services or affect networking.

On Debian/Ubuntu, **dnsmasq-base** supplies the binary without installing the
full system DNS/DHCP service. Do not start or enable the system hostapd/dnsmasq
services for this tool; it runs its own temporary instances and does not stop
existing services. Resolve any conflicts without disabling unrelated networking.

The script uses an existing non-root account for dnsmasq, trying `dnsmasq`,
`_dnsmasq`, then `nobody`. If your distribution uses another account, specify it
with `--dnsmasq-user ACCOUNT`. No system accounts are created or modified.

## 2. Open a terminal in this folder

All commands below assume the current directory contains:

```text
README.md
hotspot.py
activation_server.py
tests/
```

The folder can be copied or renamed. No firmware archive, APK, packet capture,
original research directory or hard-coded home path is required. Keep the two
Python scripts together.

If you instead run commands from a parent directory, prefix the script filename
with the actual folder name. Do not repeat that prefix after entering the folder.

## 3. Choose a Wi-Fi interface and check

If there is exactly one Wi-Fi interface, it is selected automatically:

```bash
python3 hotspot.py --check
```

To list interfaces or select one explicitly:

```bash
nmcli -f DEVICE,TYPE,STATE device status
python3 hotspot.py --check --interface wlan0
```

**`wlan0` is only an example.** Replace it with your Wi-Fi device name, which may
look quite different. Disconnect only that interface if it is currently in use:

```bash
nmcli device disconnect wlan0
```

Do not disconnect the interface carrying your remote terminal session. Save work
and preferably have a local console available for the first run.

The check validates dependencies, driver/channel support, disconnected Wi-Fi,
subnet overlap, a non-root daemon account and 3DES. It does not start an AP or
validate privileged firewall operations. Startup refuses a selected device with
IP addresses, an active connection, a Wi-Fi default route, or another network
interface sharing its radio. It also refuses an unfinished previous run or a
conflicting private firewall table.

## 4. Start and activate

```bash
sudo python3 hotspot.py --keep-logs
```

With multiple Wi-Fi devices, add `--interface YOUR_WIFI_DEVICE`, using the same
device selected during the check. After **AP READY**, the script prints:

- SSID: **Crema-Revive** (configurable).
- A generated WPA2 password, valid only for this run.
- AP address: normally **10.77.0.1**.

Connect only the Crema Touch to this AP and press its registration/continue
button. Keep the terminal open. `ACTIVATION RESPONSE SENT` means a response was
sent, **not proof that the reader accepted it**: check the device screen, open a
local DRM-free book, then stop the AP and reboot with Wi-Fi off to verify success.

### Retailer branding

Choose the code matching the device's original retailer when known:

| Code | Branding |
| --- | --- |
| `keph_yes24` | YES24; default and used in the reported successful activation |
| `keph_aladin` | Aladin |
| `keph_bandi` | Bandi & Luni's |
| `offline` | Experimental generic value; downstream reader behavior is unverified |

For example:

```bash
sudo python3 hotspot.py --shopcode keph_aladin --keep-logs
```

The retailer strings were found in firmware; not every combination is tested.
They control launcher branding, not bookstore-account authentication. Do not
enter real bookstore credentials. Factory reset erases a database-only
activation; rerun the hotspot if that happens.

### Startup handling and options

Startup waits for NetworkManager to release the selected device and for the
kernel to accept AP mode while the interface is down. Each handoff wait is
limited to 10 seconds; individual external commands also have a timeout. If
hostapd exits with `Could not configure driver mode` before enabling the AP, the
script makes up to three startup attempts. Other errors or failures after the AP
was enabled are not silently retried. It never kills or restarts global network
services. Run only one instance at a time.

Use `python3 hotspot.py --help` for all options. Common adjustments:

- `--interface DEVICE`: choose a radio rather than autodetecting.
- `--channel 6` or `--channel 11`: alternatives to channel 1, subject to the
  adapter's existing regulatory settings.
- `--ssid NAME`: change the visible AP name.
- `--subnet 192.168.77.0/24`: use another unused private /24 if the default
  `10.77.0.0/24` conflicts with a local/VPN route.
- `--dnsmasq-user ACCOUNT`: choose an existing unprivileged daemon account.
- `--keep-logs`: retain diagnostic logs after cleanup.

## 5. Stop and cleanup

Press **Ctrl+C once**, then allow a few seconds for cleanup. Normal exit,
startup/runtime errors, SIGTERM and terminal hangup trigger rollback. Further
interrupts are ignored while cleanup runs.

Cleanup stops only this tool's child process groups, deletes only its private
`table inet crema_revive`, removes its AP address/automatic route, and restores
the selected Wi-Fi interface's original type, MAC, administrative link state,
IPv6-disable setting and NetworkManager management/autoconnect settings. Normal
NetworkManager behavior may subsequently randomize the MAC or reconnect.

Generated configuration, the AP password, DHCP leases and journal are removed
from `/run/crema-revive`. No NetworkManager profiles or persistent firewall
rules are created. Installed dependency packages are not uninstalled.

No exit handler can run after **SIGKILL (`kill -9`) or power loss**. Recover an
abandoned run on the same boot with:

```bash
sudo python3 hotspot.py --cleanup
```

The root-owned journal stores original state and child PID start times; cleanup
checks process identity and refuses to run while another instance holds the
lock. Failed cleanup steps retain the journal and print a recovery command.
On a normal reboot, temporary runtime files, processes, AP addresses and the
in-memory firewall table disappear; NetworkManager reloads its persistent setup.

## Privacy, privileges and network boundaries

One sudo invocation is needed for radio, DHCP and firewall setup. The supervisor
retains root for cleanup. The HTTP emulator runs as the sudo caller, or as the
selected unprivileged daemon account for a direct root run. dnsmasq also drops
privileges. No sudoers entries or permanent file capabilities are installed.

Only the selected Wi-Fi device is reconfigured. There are no global Wi-Fi
toggles, NetworkManager restarts, Internet sharing/masquerading, or edits to
`/etc`. AP-scoped rules redirect port 80 to the unprivileged HTTP emulator and
both UDP/TCP DNS to the local resolver, including hard-coded public DNS attempts.
Only `mng.k-epub.co.kr` and `mng2.k-epub.co.kr` receive local DNS addresses;
unrelated requests are not proxied to the Internet. AP clients are blocked from
forwarding to other networks and accessing unrelated host services. Existing
firewall drops still apply and may block this tool. OTA checks are declined;
the emulator never offers firmware downloads or uploads telemetry.

Without `--keep-logs`, daemon logs are removed on exit. With it, logs are saved
to a private `crema-revive-logs-*` directory in the system temporary location,
and its path is printed. Failed radio attempts have separate
`hostapd-attempt-*.log` files. Logs can include client IP/MAC addresses, DHCP
hostnames, DNS names and the last four serial characters. The HTTP emulator does
not log full serials or decrypted personal fields. Generated configurations and
passwords are not copied into preserved logs, **but the terminal prints the AP
password**. Redact terminal output and logs before posting them publicly.

## Troubleshooting

- **Missing tools/account:** install your distribution's dependencies or select
  an existing non-root account with `--dnsmasq-user`; rerun `--check`.
- **Subnet overlap:** choose an unused private /24 with `--subnet`. Existing
  routes are not overridden.
- **AP fails to start:** inspect the hostapd log. Persistent driver-mode errors,
  radio blocks, regulatory restrictions or competing processes need investigation.
  The script does not globally unblock radios or kill other services.
- **Reader cannot see/join:** try another supported channel. The AP uses
  2.4 GHz WPA2-PSK/CCMP without mandatory PMF or 802.11n, not an open network.
- **Connects but no DHCP lease:** inspect dnsmasq logs and the existing firewall.
  Do not disable the firewall wholesale; identify a narrowly scoped adjustment.
- **DHCP works but no activation POST:** press registration/continue on the
  device. Its known vendor connectivity checks are emulated; unrelated Internet
  connectivity checks will still fail on this deliberately isolated AP.
- **Reply sent but still stuck:** record the exact screen, model, firmware and
  retailer; other firmware may have a different protocol or downstream failure.

For a bug report, include the Linux distribution, Python version, Wi-Fi
driver/adapter, exact command and relevant redacted log tail. Do not include
bookstore passwords, a full device serial, or an unreviewed packet capture.

## Tests and sharing

The test suite uses localhost high ports and mocked network operations, not an
actual AP or root privileges. OpenSSL is required for the protocol tests.

```bash
python3 -B -m unittest discover -s tests -v
```

Share this folder's source, tests, README and optional `.gitignore`. No files
outside the folder are needed. Do not bundle personal logs/captures, firmware
archives, extracted proprietary applications or device backups. The activation
key/IV and service names in the source are firmware protocol constants, not
personal account credentials; the device serial is read from each request.
