"""
temifi v1 - Wi-Fi assessment helper for authorized testing only.

Features (wrappers around aircrack-ng suite):
- List adapters and pick one to use.
- Enable/disable monitor mode via airmon-ng.
- Scan with airodump-ng.
- Capture WPA/WPA2 handshakes.
- Send deauth frames (for authorized tests only).

Run as root on Kali; tools airmon-ng/airodump-ng/aireplay-ng must be installed.
Use only against networks you own or have explicit permission to assess.
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path
import re


NAME = "temifi"
VERSION = "1.0"
LOG_DIR = Path("captures")

COLORS = {
	"reset": "\033[0m",
	"green": "\033[92m",
	"yellow": "\033[93m",
	"red": "\033[91m",
	"blue": "\033[94m",
	"cyan": "\033[96m",
	"bold": "\033[1m",
}


def c(text: str, color: str) -> str:
	return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def require_root() -> None:
	if os.geteuid() != 0:
		print(c("[!] Run this script with sudo/root privileges.", "red"))
		sys.exit(1)


def run_command(cmd: list[str]) -> int:
	print(c(f"\n[+] Running: {' '.join(shlex.quote(c) for c in cmd)}", "cyan"))
	try:
		return subprocess.call(cmd)
	except KeyboardInterrupt:
		print(c("[!] Command interrupted.", "yellow"))
		return 1


def _map_iw_types() -> dict[str, str]:
	"""Return iface -> type (managed/monitor/etc)."""
	proc = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
	iface = None
	mapping: dict[str, str] = {}
	for raw in proc.stdout.splitlines():
		line = raw.strip()
		if line.startswith("Interface "):
			iface = line.split()[1]
		elif line.startswith("type") and iface:
			parts = line.split()
			if len(parts) >= 2:
				mapping[iface] = parts[1]
	return mapping


def _map_iwconfig_modes() -> dict[str, str]:
	"""Return iface -> mode using iwconfig (helpful when iw dev reports P2P-device)."""
	proc = subprocess.run(["iwconfig"], capture_output=True, text=True, check=False)
	mapping: dict[str, str] = {}
	current_iface = None
	for raw in proc.stdout.splitlines():
		if not raw.strip():
			current_iface = None
			continue
		# Interface header starts at column 0
		m = re.match(r"^(\S+)\s+IEEE", raw)
		if m:
			current_iface = m.group(1)
			continue
		if current_iface and "Mode:" in raw:
			mode_part = raw.split("Mode:", 1)[1]
			mode = mode_part.split()[0].strip()
			if mode:
				mode = mode.replace("P2P-Device", "P2P-device")
				mapping[current_iface] = mode.lower()
	return mapping


def _map_airmon_chipset_driver() -> dict[str, tuple[str | None, str | None]]:
	"""Return iface -> (chipset, driver) using airmon-ng summary."""
	proc = subprocess.run(["airmon-ng"], capture_output=True, text=True, check=False)
	lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
	mapping: dict[str, tuple[str | None, str | None]] = {}
	for ln in lines:
		lower = ln.lower()
		# Skip header lines
		if lower.startswith("interface") or lower.startswith("phy\tinterface"):
			continue
		parts = ln.split()
		# Expected format: PHY Interface Driver Chipset...
		if len(parts) >= 4 and parts[0].startswith("phy"):
			iface = parts[1]
			driver = parts[2]
			chipset = " ".join(parts[3:]) if len(parts) > 3 else None
			mapping[iface] = (chipset, driver)
		elif len(parts) >= 3:
			# Fallback to older parsing (interface driver chipset...)
			iface = parts[0]
			driver = parts[1]
			chipset = " ".join(parts[2:]) if len(parts) > 2 else None
			mapping[iface] = (chipset, driver)
	return mapping


def _get_driver_from_ethtool(iface: str) -> str | None:
	proc = subprocess.run(["ethtool", "-i", iface], capture_output=True, text=True, check=False)
	if proc.returncode != 0:
		return None
	for line in proc.stdout.splitlines():
		if line.lower().startswith("driver:"):
			return line.split(":", 1)[1].strip() or None
	return None


def list_interfaces() -> list[tuple[str, str | None, str | None, str | None]]:
	ip_proc = subprocess.run([
		"ip",
		"-o",
		"link",
		"show",
	], capture_output=True, text=True, check=False)
	mode_map = _map_iw_types()
	iwconfig_mode_map = _map_iwconfig_modes()
	airmon_map = _map_airmon_chipset_driver()
	items: list[tuple[str, str | None, str | None, str | None]] = []
	for line in ip_proc.stdout.splitlines():
		parts = line.split(":", maxsplit=2)
		if len(parts) >= 2:
			name = parts[1].strip()
			if name == "lo":
				continue
			mode = mode_map.get(name)
			# Fallback to iwconfig-reported mode when iw reports P2P-device or missing
			if mode in {None, "P2P-device", "p2p-device", "p2p-dev"}:
				mode = iwconfig_mode_map.get(name, mode)
			# If still ambiguous, infer monitor for airmon-style suffix
			if mode in {None, "P2P-device", "p2p-device", "p2p-dev"} and name.endswith("mon"):
				mode = "monitor"
			chipset, driver = airmon_map.get(name, (None, None))
			if driver is None:
				driver = _get_driver_from_ethtool(name)
			items.append((name, mode, driver, chipset))
	return items


def choose_interface() -> str:
	adapters = list_interfaces()
	if not adapters:
		print(c("[!] No network adapters found.", "red"))
		sys.exit(1)
	print(c("Available adapters:", "bold"))
	for idx, (name, mode, driver, chipset) in enumerate(adapters, 1):
		mode_txt = mode or "?"
		driver_txt = driver or "?"
		chip_txt = chipset or "?"
		print(c(f"  {idx}. {name}", "blue") + f" (mode: {mode_txt}, driver: {driver_txt}, chipset: {chip_txt})")
	while True:
		choice = input("Select adapter number: ").strip()
		if not choice.isdigit():
			print(c("Enter a number.", "yellow"))
			continue
		num = int(choice)
		if 1 <= num <= len(adapters):
			return adapters[num - 1][0]
		print(c("Out of range.", "yellow"))


def enable_monitor_mode(adapter: str) -> str:
	iface_modes = {name: (mode or "").lower() for name, mode, _, _ in list_interfaces()}
	current_mode = iface_modes.get(adapter, "")
	if current_mode == "monitor" or adapter.endswith("mon"):
		print(c(f"[*] {adapter} already in monitor mode; skipping 'airmon-ng start'.", "yellow"))
		return adapter

	resp = input("Run 'airmon-ng check kill' to stop interfering services? [Y/n]: ").strip().lower()
	if resp in {"", "y", "yes"}:
		run_command(["airmon-ng", "check", "kill"])
	else:
		print(c("[!] Skipping 'airmon-ng check kill'; if capture fails, rerun with it.", "yellow"))
	run_command(["airmon-ng", "start", adapter])
	mon = f"{adapter}mon"
	print(c(f"[+] Monitor mode requested on {mon} (verify with iwconfig).", "green"))
	return mon


def disable_monitor_mode(adapter: str) -> None:
	run_command(["airmon-ng", "stop", adapter])
	print(c(f"[+] Monitor mode stopped for {adapter}.", "green"))


def _parse_iw_scan(stdout: str) -> list[dict[str, str]]:
	networks: list[dict[str, str]] = []
	current: dict[str, str] = {}
	for raw in stdout.splitlines():
		line = raw.strip()
		if not line:
			continue
		if line.startswith("BSS "):
			if current:
				networks.append(current)
			current = {"bssid": line.split()[1]}
		elif line.startswith("freq:"):
			current["freq"] = line.split(":", 1)[1].strip()
		elif line.startswith("signal:"):
			current["signal"] = line.split(":", 1)[1].strip().split()[0]
		elif line.startswith("SSID:"):
			current["ssid"] = line.split(":", 1)[1].strip()
	if current:
		networks.append(current)
	return networks


def _native_scan(mon_iface: str) -> None:
	candidate = mon_iface[:-3] if mon_iface.endswith("mon") else mon_iface
	iface_names = [name for name, _, _, _ in list_interfaces()]
	if not iface_names:
		print(c("[!] No interfaces available for native scan.", "red"))
		return
	print(c("Available interfaces for native scan (from 'iw dev'):", "bold"))
	for name in iface_names:
		print(c(f"  - {name}", "blue"))
	default_iface = candidate if candidate in iface_names else (mon_iface if mon_iface in iface_names else iface_names[0])
	resp = input(f"Interface for native scan [{default_iface}]: ").strip()
	if resp and resp in iface_names:
		iface = resp
	elif resp:
		print(f"[!] '{resp}' not found; using {default_iface} instead.")
		iface = default_iface
	else:
		iface = default_iface

	def _run_scan(target: str) -> subprocess.CompletedProcess[str]:
		return subprocess.run(["iw", "dev", target, "scan"], capture_output=True, text=True, check=False)

	print(f"[*] Running native scan with 'iw dev {iface} scan' (Ctrl+C to stop)...")
	proc = _run_scan(iface)
	if proc.returncode != 0:
		stderr = proc.stderr.strip()
		print(c(f"[!] iw scan failed (code {proc.returncode}).", "red"))
		if stderr:
			print(stderr)
		if "No such device" in stderr:
			print(c("[*] Bringing interface up and retrying...", "cyan"))
			subprocess.run(["ip", "link", "set", iface, "up"], check=False)
			proc = _run_scan(iface)
			if proc.returncode == 0:
				stderr = ""
			else:
				stderr = proc.stderr.strip()
				print(c(f"[!] iw scan retry failed (code {proc.returncode}).", "red"))
				if stderr:
					print(stderr)
				if iface != mon_iface and mon_iface in iface_names:
					print(c(f"[*] Retrying with interface '{mon_iface}'...", "cyan"))
					proc = _run_scan(mon_iface)
					if proc.returncode != 0:
						print(c(f"[!] iw scan retry failed (code {proc.returncode}).", "red"))
						if proc.stderr:
							print(proc.stderr.strip())
						print(c("[i] Try putting the interface back to managed mode or use option 1 (airodump-ng) instead.", "yellow"))
						return
				else:
					print(c("[i] Native scan not supported on this interface. Use option 1 (airodump-ng) instead.", "yellow"))
					return
		if "Device or resource busy" in stderr:
			print(c("[*] Attempting iface down/up then retry (may break existing connections)...", "cyan"))
			subprocess.run(["ip", "link", "set", iface, "down"], check=False)
			subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False)
			subprocess.run(["ip", "link", "set", iface, "up"], check=False)
			proc = _run_scan(iface)
			if proc.returncode != 0:
				print(c(f"[!] iw scan retry failed (code {proc.returncode}).", "red"))
				if proc.stderr:
					print(proc.stderr.strip())
				print(c("[i] Native scan still blocked; use option 1 (airodump-ng).", "yellow"))
				return
		if "No such device" in stderr and iface != mon_iface:
			alt = mon_iface
			print(c(f"[*] Retrying with interface '{alt}'...", "cyan"))
			proc = _run_scan(alt)
			if proc.returncode != 0:
				print(c(f"[!] iw scan retry failed (code {proc.returncode}).", "red"))
				if proc.stderr:
					print(proc.stderr.strip())
				print(c("[i] Try putting the interface back to managed mode or use option 1 (airodump-ng) instead.", "yellow"))
				return
		else:
			print(c("[i] Native scan not supported on this interface. Use option 1 (airodump-ng) instead.", "yellow"))
			return
	networks = _parse_iw_scan(proc.stdout)
	if not networks:
		print(c("[!] No networks parsed from iw scan output.", "yellow"))
		return
	try:
		networks.sort(key=lambda n: float(n.get("signal", "-100")), reverse=True)
	except ValueError:
		pass
	print("\nFound networks (best signal first):")
	for idx, net in enumerate(networks, 1):
		ssid = net.get("ssid", "<hidden>")
		bssid = net.get("bssid", "?")
		freq = net.get("freq", "?")
		signal = net.get("signal", "?")
		print(c(f"  {idx}. SSID: {ssid}", "blue") + f" | BSSID: {bssid} | Freq: {freq} MHz | Signal: {signal} dBm")


def _airodump_scan(mon_iface: str) -> None:
	print(c("Select band to scan:", "bold"))
	print("  1. 2.4 GHz only")
	print("  2. 5 GHz only")
	print("  3. Both 2.4/5 GHz")
	band_choice = input("Choice [1/2/3]: ").strip()
	band_map = {
		"1": "bg",  # 2.4 GHz
		"2": "a",   # 5 GHz
		"3": "abg", # both
	}
	band = band_map.get(band_choice, "abg")
	print(c(f"[*] Starting airodump-ng scan on band '{band}' (Ctrl+C to stop)...", "cyan"))
	run_command(["airodump-ng", "--band", band, mon_iface])


def scan_networks(mon_iface: str) -> None:
	print(c("Select scan method:", "bold"))
	print("  1. Use airodump-ng (recommended)")
	print("  2. Native scan via iw (no airodump-ng)")
	choice = input("Choice [1/2]: ").strip()
	if choice == "2":
		_native_scan(mon_iface)
	else:
		_airodump_scan(mon_iface)


def capture_handshake(mon_iface: str) -> None:
	bssid = input("Target BSSID (AP MAC): ").strip()
	channel = input("Channel: ").strip()
	prefix = input("Output prefix (default capture): ").strip() or "capture"
	LOG_DIR.mkdir(exist_ok=True)
	filepath = LOG_DIR / prefix
	cmd = [
		"airodump-ng",
		"--bssid",
		bssid,
		"--channel",
		channel,
		"--write",
		str(filepath),
		mon_iface,
	]
	print(c("[*] Capturing handshake (Ctrl+C when handshake observed)...", "cyan"))
	run_command(cmd)
	print(c(f"[+] Capture saved to {filepath.with_suffix('.cap')} and .csv/.kismet files.", "green"))


def send_deauth(mon_iface: str) -> None:
	bssid = input("Target BSSID (AP MAC): ").strip()
	station = input("Station MAC (or leave blank for broadcast): ").strip()
	count = input("Deauth count (e.g., 10, 0 for continuous): ").strip() or "10"
	cmd = ["aireplay-ng", "--deauth", count, "-a", bssid]
	if station:
		cmd.extend(["-c", station])
	cmd.append(mon_iface)
	print(c("[*] Deauth will disrupt clients. Use only with permission.", "yellow"))
	run_command(cmd)


def restart_network_manager() -> None:
	print(c("[*] Restarting NetworkManager (may disrupt connectivity)...", "yellow"))
	run_command(["systemctl", "restart", "NetworkManager"])
	print(c("[+] NetworkManager restart requested.", "green"))


def menu(mon_iface: str) -> None:
	actions = {
		"1": ("Scan networks", scan_networks),
		"2": ("Capture WPA handshake", capture_handshake),
		"3": ("Send deauth frames (aireplay-ng)", send_deauth),
		"4": ("Disable monitor mode and exit", None),
		"5": ("Restart NetworkManager", lambda _: restart_network_manager()),
	}
	while True:
		print(c("\nSelect action:", "bold"))
		for key, (label, _) in actions.items():
			print(c(f"  {key}. {label}", "blue"))
		choice = input("Choice: ").strip()
		if choice == "4":
			break
		if choice in actions:
			_, func = actions[choice]
			if func:
				func(mon_iface)
		else:
			print(c("[!] Invalid choice.", "yellow"))


def main() -> None:
	print(c(f"{NAME} v{VERSION} - authorized Wi-Fi testing helper", "bold"))
	require_root()
	adapter = choose_interface()
	mon_iface = enable_monitor_mode(adapter)
	try:
		menu(mon_iface)
	finally:
		disable_monitor_mode(mon_iface)
		print(c("[+] Done.", "green"))


if __name__ == "__main__":
	main()
