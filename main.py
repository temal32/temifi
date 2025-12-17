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


NAME = "temifi"
VERSION = "1.0"
LOG_DIR = Path("captures")


def require_root() -> None:
	if os.geteuid() != 0:
		print("[!] Run this script with sudo/root privileges.")
		sys.exit(1)


def run_command(cmd: list[str]) -> int:
	print(f"\n[+] Running: {' '.join(shlex.quote(c) for c in cmd)}")
	try:
		return subprocess.call(cmd)
	except KeyboardInterrupt:
		print("[!] Command interrupted.")
		return 1


def list_interfaces() -> list[str]:
	proc = subprocess.run([
		"ip",
		"-o",
		"link",
		"show",
	], capture_output=True, text=True, check=False)
	names = []
	for line in proc.stdout.splitlines():
		parts = line.split(":", maxsplit=2)
		if len(parts) >= 2:
			name = parts[1].strip()
			if name != "lo":
				names.append(name)
	return names


def choose_interface() -> str:
	adapters = list_interfaces()
	if not adapters:
		print("[!] No network adapters found.")
		sys.exit(1)
	print("Available adapters:")
	for idx, name in enumerate(adapters, 1):
		print(f"  {idx}. {name}")
	while True:
		choice = input("Select adapter number: ").strip()
		if not choice.isdigit():
			print("Enter a number.")
			continue
		num = int(choice)
		if 1 <= num <= len(adapters):
			return adapters[num - 1]
		print("Out of range.")


def enable_monitor_mode(adapter: str) -> str:
	run_command(["airmon-ng", "check", "kill"])
	run_command(["airmon-ng", "start", adapter])
	mon = f"{adapter}mon"
	print(f"[+] Monitor mode requested on {mon} (verify with iwconfig).")
	return mon


def disable_monitor_mode(adapter: str) -> None:
	run_command(["airmon-ng", "stop", adapter])
	print(f"[+] Monitor mode stopped for {adapter}.")


def scan_networks(mon_iface: str) -> None:
	print("[*] Starting airodump-ng scan (Ctrl+C to stop)...")
	run_command(["airodump-ng", mon_iface])


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
	print("[*] Capturing handshake (Ctrl+C when handshake observed)...")
	run_command(cmd)
	print(f"[+] Capture saved to {filepath.with_suffix('.cap')} and .csv/.kismet files.")


def send_deauth(mon_iface: str) -> None:
	bssid = input("Target BSSID (AP MAC): ").strip()
	station = input("Station MAC (or leave blank for broadcast): ").strip()
	count = input("Deauth count (e.g., 10, 0 for continuous): ").strip() or "10"
	cmd = ["aireplay-ng", "--deauth", count, "-a", bssid]
	if station:
		cmd.extend(["-c", station])
	cmd.append(mon_iface)
	print("[*] Deauth will disrupt clients. Use only with permission.")
	run_command(cmd)


def menu(mon_iface: str) -> None:
	actions = {
		"1": ("Scan networks (airodump-ng)", scan_networks),
		"2": ("Capture WPA handshake", capture_handshake),
		"3": ("Send deauth frames (aireplay-ng)", send_deauth),
		"4": ("Disable monitor mode and exit", None),
	}
	while True:
		print("\nSelect action:")
		for key, (label, _) in actions.items():
			print(f"  {key}. {label}")
		choice = input("Choice: ").strip()
		if choice == "4":
			break
		if choice in actions:
			_, func = actions[choice]
			if func:
				func(mon_iface)
		else:
			print("[!] Invalid choice.")


def main() -> None:
	print(f"{NAME} v{VERSION} - authorized Wi-Fi testing helper")
	require_root()
	adapter = choose_interface()
	mon_iface = enable_monitor_mode(adapter)
	try:
		menu(mon_iface)
	finally:
		disable_monitor_mode(mon_iface)
		print("[+] Done.")


if __name__ == "__main__":
	main()
