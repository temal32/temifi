#!/usr/bin/env python3
"""
temifi GUI (defensive audit edition)

Uses functions/vars from main.py where safe:
- main.NAME, main.VERSION, main.LOG_DIR
- main.list_interfaces()

Does NOT implement handshake capture or deauth.

Run on Linux. For best results:
  sudo python3 gui.py
"""

from __future__ import annotations

import csv
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tkinter import Tk, StringVar, Text, filedialog, messagebox
from tkinter import ttk

# Import existing script
import main


# --------------------------- Theme ---------------------------

@dataclass(frozen=True)
class Theme:
    bg: str = "#0f1115"
    panel: str = "#151823"
    panel2: str = "#1b2030"
    fg: str = "#e6e6e6"
    muted: str = "#b7bcc7"
    border: str = "#2a3042"
    accent: str = "#7aa2f7"
    ok: str = "#9ece6a"
    warn: str = "#e0af68"
    danger: str = "#f7768e"


THEME = Theme()


def apply_dark_theme(root: Tk) -> ttk.Style:
    root.configure(bg=THEME.bg)
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    style.configure(".", background=THEME.bg, foreground=THEME.fg, fieldbackground=THEME.panel2)

    style.configure("TFrame", background=THEME.bg)
    style.configure("Card.TFrame", background=THEME.panel, borderwidth=1, relief="solid")

    style.configure("TLabel", background=THEME.bg, foreground=THEME.fg)
    style.configure("Muted.TLabel", foreground=THEME.muted)
    style.configure("Title.TLabel", font=("TkDefaultFont", 14, "bold"))
    style.configure("H2.TLabel", font=("TkDefaultFont", 11, "bold"))

    style.configure(
        "TButton",
        background=THEME.panel2,
        foreground=THEME.fg,
        borderwidth=0,
        padding=(12, 8),
        focusthickness=2,
        focuscolor=THEME.accent,
    )
    style.map(
        "TButton",
        background=[("active", "#232a3d"), ("pressed", "#2a3350"), ("disabled", "#141926")],
        foreground=[("disabled", "#6f7687")],
    )

    style.configure(
        "Accent.TButton",
        background=THEME.accent,
        foreground="#0b1020",
        padding=(12, 8),
        borderwidth=0,
    )
    style.map(
        "Accent.TButton",
        background=[("active", "#8bb0ff"), ("pressed", "#6c95f5"), ("disabled", "#141926")],
        foreground=[("disabled", "#6f7687")],
    )

    style.configure(
        "Danger.TButton",
        background=THEME.danger,
        foreground="#1a0b10",
        padding=(12, 8),
        borderwidth=0,
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#ff8ea2"), ("pressed", "#f06a85"), ("disabled", "#141926")],
        foreground=[("disabled", "#6f7687")],
    )

    style.configure("TCombobox", padding=(10, 6))
    style.configure("TEntry", padding=(10, 6))

    style.configure(
        "Treeview",
        background=THEME.panel2,
        fieldbackground=THEME.panel2,
        foreground=THEME.fg,
        rowheight=26,
        bordercolor=THEME.border,
        lightcolor=THEME.border,
        darkcolor=THEME.border,
    )
    style.configure(
        "Treeview.Heading",
        background=THEME.panel,
        foreground=THEME.fg,
        relief="flat",
        padding=(10, 6),
    )
    style.map("Treeview", background=[("selected", "#2b3a5a")], foreground=[("selected", THEME.fg)])
    style.map("Treeview.Heading", background=[("active", "#1f2538")])

    style.configure("TNotebook", background=THEME.bg, borderwidth=0)
    style.configure("TNotebook.Tab", background=THEME.panel, foreground=THEME.fg, padding=(12, 8))
    style.map(
        "TNotebook.Tab",
        background=[("selected", THEME.panel2), ("active", "#1f2538")],
        foreground=[("selected", THEME.fg)],
    )

    style.configure("TSeparator", background=THEME.border)
    return style


# --------------------------- Parsing helpers ---------------------------

def freq_to_band(freq_mhz: int) -> str:
    if freq_mhz < 3000:
        return "2.4 GHz"
    if freq_mhz < 5900:
        return "5 GHz"
    return "6 GHz"


def freq_to_channel(freq_mhz: int) -> int | None:
    # 2.4 GHz
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5

    # 5 GHz common formula: channel = (freq - 5000)/5
    if 4915 <= freq_mhz <= 5895:
        ch = (freq_mhz - 5000) // 5
        return int(ch) if ch > 0 else None

    # 6 GHz: channel 1 starts at 5955 MHz, 5 MHz steps
    if 5955 <= freq_mhz <= 7115:
        return int((freq_mhz - 5950) // 5)

    return None


def parse_iw_scan_extended(stdout: str) -> list[dict[str, Any]]:
    """
    Parses `iw dev <iface> scan` into structured results:
    ssid, bssid, freq, channel, band, signal, security
    """
    nets: list[dict[str, Any]] = []
    current: dict[str, Any] = {}

    has_rsn = False
    has_wpa = False
    akm_tokens: set[str] = set()

    def finalize():
        nonlocal current, has_rsn, has_wpa, akm_tokens
        if not current:
            return

        # Determine security label
        sec = "OPEN"
        tok = {t.upper() for t in akm_tokens}
        if has_rsn or has_wpa:
            is_enterprise = any(x in tok for x in ["802.1X", "EAP"])
            has_psk = "PSK" in tok
            has_sae = "SAE" in tok

            if is_enterprise:
                sec = "Enterprise (802.1X)"
            elif has_psk and has_sae:
                sec = "WPA2/WPA3 Mixed"
            elif has_sae:
                sec = "WPA3-SAE"
            elif has_psk:
                sec = "WPA2-PSK"
            else:
                sec = "WPA/WPA2 (unknown AKM)"

        current["security"] = sec

        # Normalize / fill fields
        try:
            f = int(current.get("freq_mhz")) if current.get("freq_mhz") is not None else None
        except Exception:
            f = None
        if f:
            current["band"] = freq_to_band(f)
            current["channel"] = current.get("channel") or freq_to_channel(f)
            current["freq_mhz"] = f
        else:
            current["band"] = current.get("band") or "?"
            current["channel"] = current.get("channel") or None
            current["freq_mhz"] = current.get("freq_mhz") or None

        current["ssid"] = current.get("ssid") or "<hidden>"
        current["bssid"] = current.get("bssid") or "?"

        # Signal as float if possible
        sig_raw = current.get("signal_dbm")
        try:
            current["signal_dbm"] = float(sig_raw) if sig_raw is not None else None
        except Exception:
            current["signal_dbm"] = None

        nets.append(current)

        # reset
        current = {}
        has_rsn = False
        has_wpa = False
        akm_tokens = set()

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("BSS "):
            finalize()
            # "BSS <bssid>(on <iface>)"
            parts = line.split()
            if len(parts) >= 2:
                bssid = parts[1].split("(", 1)[0]
                current = {"bssid": bssid}
            else:
                current = {}
            continue

        if line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip()
            continue

        if line.startswith("freq:"):
            try:
                current["freq_mhz"] = int(line.split(":", 1)[1].strip())
            except Exception:
                current["freq_mhz"] = None
            continue

        # Sometimes channel appears explicitly:
        # "DS Parameter set: channel 6" or "primary channel: 36"
        m = re.search(r"\bchannel\s+(\d+)\b", line, flags=re.IGNORECASE)
        if m:
            try:
                current["channel"] = int(m.group(1))
            except Exception:
                pass

        if line.startswith("signal:"):
            # e.g. "signal: -47.00 dBm"
            val = line.split(":", 1)[1].strip().split()[0]
            current["signal_dbm"] = val
            continue

        if line.startswith("RSN:"):
            has_rsn = True
            continue
        if line.startswith("WPA:"):
            has_wpa = True
            continue

        # AKM / auth suites lines often look like:
        # "* Authentication suites: SAE" or "* AKM suites: PSK SAE"
        if line.startswith("*"):
            if "Authentication suites:" in line or "AKM suites:" in line:
                tail = line.split(":", 1)[1].strip()
                # tokens may be separated by spaces
                for tok in tail.replace(",", " ").split():
                    akm_tokens.add(tok)
            continue

    finalize()
    return nets


def recommend_24ghz_channel(nets: list[dict[str, Any]]) -> tuple[int | None, dict[int, int]]:
    """
    Very simple recommendation:
    - Count observed APs on channels 1..13 (2.4GHz)
    - Recommend among {1,6,11} the lowest-count channel
    """
    counts: dict[int, int] = {ch: 0 for ch in range(1, 14)}
    for n in nets:
        if n.get("band") != "2.4 GHz":
            continue
        ch = n.get("channel")
        if isinstance(ch, int) and 1 <= ch <= 13:
            counts[ch] += 1

    candidates = [1, 6, 11]
    best = min(candidates, key=lambda c: counts.get(c, 0)) if any(counts.values()) else None
    return best, counts


# --------------------------- App ---------------------------

class TemifiGUI:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title(f"{main.NAME} v{main.VERSION} — GUI (Wi-Fi Audit)")
        self.root.geometry("1120x720")
        self.root.minsize(1020, 640)

        apply_dark_theme(root)

        self.selected_iface = StringVar(value="")
        self.status = StringVar(value="Ready.")
        self._scan_results: list[dict[str, Any]] = []
        self._last_scan_iface: str | None = None

        self._build_layout()
        self._preflight_and_load()

    # ---- UI ----

    def _build_layout(self) -> None:
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=16, pady=(16, 10))

        ttk.Label(top, text=f"{main.NAME} — Wi-Fi Audit GUI", style="Title.TLabel").pack(side="left")
        ttk.Label(
            top,
            text="Defensive scans & checks only (no deauth/handshake capture)",
            style="Muted.TLabel",
        ).pack(side="left", padx=(12, 0))

        main_area = ttk.Frame(self.root)
        main_area.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        paned = ttk.Panedwindow(main_area, orient="horizontal")
        paned.pack(fill="both", expand=True)

        self.sidebar = ttk.Frame(paned, style="Card.TFrame")
        self.content = ttk.Frame(paned, style="Card.TFrame")
        paned.add(self.sidebar, weight=1)
        paned.add(self.content, weight=4)

        self._build_sidebar()
        self._build_tabs()

        status_bar = ttk.Frame(self.root)
        status_bar.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Label(status_bar, textvariable=self.status, style="Muted.TLabel").pack(side="left")

    def _build_sidebar(self) -> None:
        box = ttk.Frame(self.sidebar)
        box.pack(fill="both", expand=True, padx=14, pady=14)

        ttk.Label(box, text="Interface", style="H2.TLabel").pack(anchor="w")
        self.iface_combo = ttk.Combobox(box, textvariable=self.selected_iface, state="readonly", values=[])
        self.iface_combo.pack(fill="x", pady=(8, 10))

        row = ttk.Frame(box)
        row.pack(fill="x", pady=(0, 10))
        ttk.Button(row, text="Refresh", command=self.refresh_interfaces).pack(side="left")
        ttk.Button(row, text="Captures Folder", command=self.open_captures_dir).pack(side="left", padx=(8, 0))

        ttk.Separator(box).pack(fill="x", pady=12)

        ttk.Label(box, text="Actions", style="H2.TLabel").pack(anchor="w")
        ttk.Button(box, text="Scan (iw)", style="Accent.TButton", command=self.native_scan).pack(fill="x", pady=(10, 8))
        ttk.Button(box, text="Get Link Info", command=self.refresh_link_info).pack(fill="x", pady=6)

        ttk.Separator(box).pack(fill="x", pady=12)

        ttk.Button(box, text="Export Scan CSV", command=self.export_scan_csv).pack(fill="x", pady=6)
        ttk.Button(box, text="Export Audit Report (MD)", command=self.export_audit_report).pack(fill="x", pady=6)

        ttk.Separator(box).pack(fill="x", pady=12)

        ttk.Button(box, text="Restart NetworkManager", command=self.restart_network_manager).pack(fill="x", pady=6)
        ttk.Button(box, text="Quit", style="Danger.TButton", command=self.root.quit).pack(fill="x", pady=(10, 0))

        note = (
            "Tips:\n"
            "• Run with sudo for best scan reliability.\n"
            "• Prefer WPA3-SAE, disable WPS, use a\n"
            "  strong passphrase, update firmware.\n"
            "• Use 2.4 GHz channels 1/6/11."
        )
        ttk.Label(box, text=note, style="Muted.TLabel", justify="left").pack(anchor="w", pady=(14, 0))

    def _build_tabs(self) -> None:
        box = ttk.Frame(self.content)
        box.pack(fill="both", expand=True, padx=14, pady=14)

        self.nb = ttk.Notebook(box)
        self.nb.pack(fill="both", expand=True)

        # Adapters
        self.tab_adapters = ttk.Frame(self.nb)
        self.nb.add(self.tab_adapters, text="Adapters")

        self.adapters_tree = ttk.Treeview(
            self.tab_adapters,
            columns=("mode", "driver", "chipset"),
            show="headings",
            selectmode="browse",
        )
        for col, label, w in [
            ("mode", "Mode", 120),
            ("driver", "Driver", 160),
            ("chipset", "Chipset", 520),
        ]:
            self.adapters_tree.heading(col, text=label)
            self.adapters_tree.column(col, width=w, anchor="w", stretch=True)
        self.adapters_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.adapters_tree.bind("<<TreeviewSelect>>", self._on_adapter_select)

        # Scan results
        self.tab_scan = ttk.Frame(self.nb)
        self.nb.add(self.tab_scan, text="Scan Results")

        scan_top = ttk.Frame(self.tab_scan)
        scan_top.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(scan_top, text="Results", style="H2.TLabel").pack(side="left")
        self.scan_count_lbl = ttk.Label(scan_top, text="0 networks", style="Muted.TLabel")
        self.scan_count_lbl.pack(side="left", padx=(10, 0))

        self.scan_tree = ttk.Treeview(
            self.tab_scan,
            columns=("ssid", "security", "band", "channel", "freq", "signal", "bssid"),
            show="headings",
            selectmode="browse",
        )
        cols = [
            ("ssid", "SSID", 240),
            ("security", "Security", 160),
            ("band", "Band", 90),
            ("channel", "Ch", 60),
            ("freq", "Freq (MHz)", 100),
            ("signal", "Signal (dBm)", 110),
            ("bssid", "BSSID", 220),
        ]
        for col, label, w in cols:
            self.scan_tree.heading(col, text=label)
            self.scan_tree.column(col, width=w, anchor="w", stretch=True)
        self.scan_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Analysis
        self.tab_analysis = ttk.Frame(self.nb)
        self.nb.add(self.tab_analysis, text="Analysis")

        ana_box = ttk.Frame(self.tab_analysis)
        ana_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.reco_lbl = ttk.Label(ana_box, text="Run a scan to see recommendations.", style="Muted.TLabel", justify="left")
        self.reco_lbl.pack(anchor="w", pady=(0, 10))

        self.chan_tree = ttk.Treeview(
            ana_box,
            columns=("ch", "count"),
            show="headings",
            selectmode="none",
            height=10,
        )
        self.chan_tree.heading("ch", text="2.4 GHz Channel")
        self.chan_tree.heading("count", text="Observed APs")
        self.chan_tree.column("ch", width=160, anchor="w")
        self.chan_tree.column("count", width=160, anchor="w")
        self.chan_tree.pack(anchor="w")

        # Link info
        self.tab_link = ttk.Frame(self.nb)
        self.nb.add(self.tab_link, text="Link Info")

        link_box = ttk.Frame(self.tab_link)
        link_box.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(link_box, text="Current connection (iw dev <iface> link)", style="H2.TLabel").pack(anchor="w")
        self.link_text = Text(
            link_box,
            bg=THEME.panel2,
            fg=THEME.fg,
            insertbackground=THEME.fg,
            relief="flat",
            wrap="word",
            height=12,
        )
        self.link_text.pack(fill="both", expand=True, pady=(8, 0))
        self._set_link_text("Select an interface and click “Get Link Info”.")

        # Logs
        self.tab_logs = ttk.Frame(self.nb)
        self.nb.add(self.tab_logs, text="Logs")

        self.log = Text(
            self.tab_logs,
            bg=THEME.panel2,
            fg=THEME.fg,
            insertbackground=THEME.fg,
            relief="flat",
            wrap="word",
        )
        self.log.pack(fill="both", expand=True, padx=10, pady=10)
        self._log("GUI started.")

    # ---- helpers ----

    def _set_status(self, msg: str) -> None:
        self.status.set(msg)

    def _log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _run_thread(self, fn, on_done=None) -> None:
        def runner():
            try:
                res = fn()
                if on_done:
                    self.root.after(0, lambda: on_done(res, None))
            except Exception as e:
                if on_done:
                    self.root.after(0, lambda: on_done(None, e))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=runner, daemon=True).start()

    def _set_link_text(self, text: str) -> None:
        self.link_text.delete("1.0", "end")
        self.link_text.insert("end", text)

    # ---- preflight ----

    def _preflight_and_load(self) -> None:
        if os.name != "posix":
            messagebox.showerror("Unsupported", "This GUI targets Linux (iw/ip/systemctl).")
            self.root.quit()
            return

        needed = ["iw", "ip", "systemctl"]
        missing = [c for c in needed if shutil.which(c) is None]
        if missing:
            messagebox.showerror("Missing tools", f"Missing required tools: {', '.join(missing)}")
            self.root.quit()
            return

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            self._set_status("Running without root — scans may fail. Try: sudo python3 gui.py")
            self._log("Warning: not running as root.")
        else:
            self._set_status("Ready (root detected).")

        self.refresh_interfaces()

    # ---- adapters ----

    def refresh_interfaces(self) -> None:
        self._set_status("Refreshing interfaces…")
        self._log("Refreshing interface list…")

        def work():
            return main.list_interfaces()

        def done(adapters, err):
            if err:
                self._set_status("Failed to refresh.")
                self._log(f"Error: {err}")
                messagebox.showerror("Error", f"Failed to list interfaces:\n{err}")
                return

            adapters = adapters or []
            self.adapters_tree.delete(*self.adapters_tree.get_children())

            names: list[str] = []
            for name, mode, driver, chipset in adapters:
                names.append(name)
                self.adapters_tree.insert("", "end", iid=name, values=(mode or "?", driver or "?", chipset or "?"))

            self.iface_combo["values"] = names
            if names and self.selected_iface.get() not in names:
                self.selected_iface.set(names[0])

            self._set_status(f"Loaded {len(names)} interface(s).")
            self._log(f"Loaded {len(names)} interface(s).")

        self._run_thread(work, on_done=done)

    def _on_adapter_select(self, _evt=None) -> None:
        sel = self.adapters_tree.selection()
        if not sel:
            return
        self.selected_iface.set(sel[0])
        self._log(f"Selected interface: {sel[0]}")

    # ---- scan ----

    def native_scan(self) -> None:
        iface = self.selected_iface.get().strip()
        if not iface:
            messagebox.showwarning("No interface", "Select an interface first.")
            return

        self._set_status(f"Scanning on {iface}…")
        self._log(f"Running: iw dev {iface} scan")

        def work():
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, text=True, check=False)
            proc = subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, check=False)
            return proc

        def done(proc: subprocess.CompletedProcess[str], err):
            if err:
                self._set_status("Scan failed.")
                self._log(f"Scan error: {err}")
                messagebox.showerror("Scan error", str(err))
                return

            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip() or "(no stderr)"
                self._set_status("Scan failed.")
                self._log(f"iw scan failed (code {proc.returncode}): {stderr}")
                messagebox.showerror(
                    "Scan failed",
                    f"`iw` returned {proc.returncode}.\n\n{stderr}\n\n"
                    "Try running as root, or temporarily disconnect / disable power saving.",
                )
                return

            nets = parse_iw_scan_extended(proc.stdout)

            # Sort by signal desc (e.g. -40 better than -80)
            def sig(n: dict[str, Any]) -> float:
                v = n.get("signal_dbm")
                return float(v) if isinstance(v, (int, float)) else -1000.0

            nets.sort(key=sig, reverse=True)

            self._scan_results = nets
            self._last_scan_iface = iface

            self.scan_tree.delete(*self.scan_tree.get_children())
            for i, n in enumerate(nets, start=1):
                ssid = n.get("ssid", "<hidden>")
                sec = n.get("security", "?")
                band = n.get("band", "?")
                ch = n.get("channel")
                freq = n.get("freq_mhz")
                sigv = n.get("signal_dbm")
                bssid = n.get("bssid", "?")

                self.scan_tree.insert(
                    "",
                    "end",
                    iid=f"n{i}",
                    values=(
                        ssid,
                        sec,
                        band,
                        "" if ch is None else str(ch),
                        "" if freq is None else str(freq),
                        "" if sigv is None else f"{sigv:.1f}",
                        bssid,
                    ),
                )

            self.scan_count_lbl.config(text=f"{len(nets)} networks")
            self._set_status(f"Scan complete: {len(nets)} networks.")
            self._log(f"Scan complete: {len(nets)} networks parsed.")
            self.nb.select(self.tab_scan)

            self._refresh_analysis()

        self._run_thread(work, on_done=done)

    def _refresh_analysis(self) -> None:
        nets = self._scan_results
        best, counts = recommend_24ghz_channel(nets)

        self.chan_tree.delete(*self.chan_tree.get_children())
        for ch in range(1, 14):
            self.chan_tree.insert("", "end", values=(str(ch), str(counts.get(ch, 0))))

        # Basic findings
        weak_open = [n for n in nets if n.get("security") == "OPEN"]
        wpa2_only = [n for n in nets if n.get("security") == "WPA2-PSK"]
        wpa3 = [n for n in nets if n.get("security") in {"WPA3-SAE", "WPA2/WPA3 Mixed"}]

        reco_lines = []
        if best is not None:
            reco_lines.append(f"2.4 GHz recommendation: set your router to channel **{best}** (among 1/6/11, least observed).")
        else:
            reco_lines.append("2.4 GHz recommendation: not enough data (no 2.4 GHz networks parsed).")

        reco_lines.append("")
        reco_lines.append(f"Observed: {len(weak_open)} open networks, {len(wpa2_only)} WPA2-PSK networks, {len(wpa3)} WPA3/mixed networks.")

        reco_lines.append("")
        reco_lines.append("Hardening checklist (router side):")
        reco_lines.append("• Prefer WPA3-SAE (or WPA2/WPA3 mixed if you must support older devices).")
        reco_lines.append("• Disable WPS.")
        reco_lines.append("• Use a long, unique passphrase (16+ chars).")
        reco_lines.append("• Update router firmware; disable legacy modes (WEP/WPA).")
        reco_lines.append("• Separate guest/IoT network; enable client isolation on guest.")

        self.reco_lbl.config(text="\n".join(reco_lines))

    # ---- link info ----

    def refresh_link_info(self) -> None:
        iface = self.selected_iface.get().strip()
        if not iface:
            messagebox.showwarning("No interface", "Select an interface first.")
            return

        self._set_status(f"Fetching link info for {iface}…")
        self._log(f"Running: iw dev {iface} link")

        def work():
            return subprocess.run(["iw", "dev", iface, "link"], capture_output=True, text=True, check=False)

        def done(proc, err):
            if err:
                self._set_status("Link info failed.")
                self._log(f"Error: {err}")
                messagebox.showerror("Error", str(err))
                return

            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip() or "(no stderr)"
                self._set_status("Link info failed.")
                self._log(f"iw link failed (code {proc.returncode}): {stderr}")
                self._set_link_text(f"Failed to read link info.\n\n{stderr}")
                return

            out = (proc.stdout or "").strip()
            if not out:
                out = "No output."
            self._set_status("Link info updated.")
            self._set_link_text(out)
            self.nb.select(self.tab_link)

        self._run_thread(work, on_done=done)

    # ---- exports ----

    def export_scan_csv(self) -> None:
        if not self._scan_results:
            messagebox.showinfo("No results", "Run a scan first.")
            return

        default_name = f"temifi_scan_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        path = filedialog.asksaveasfilename(
            title="Export scan results to CSV",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=["ssid", "bssid", "security", "band", "channel", "freq_mhz", "signal_dbm"],
                )
                w.writeheader()
                for n in self._scan_results:
                    w.writerow(
                        {
                            "ssid": n.get("ssid", ""),
                            "bssid": n.get("bssid", ""),
                            "security": n.get("security", ""),
                            "band": n.get("band", ""),
                            "channel": n.get("channel", ""),
                            "freq_mhz": n.get("freq_mhz", ""),
                            "signal_dbm": n.get("signal_dbm", ""),
                        }
                    )
            self._set_status(f"Exported CSV: {path}")
            self._log(f"Exported CSV: {path}")
        except Exception as e:
            self._log(f"CSV export failed: {e}")
            messagebox.showerror("Export failed", str(e))

    def export_audit_report(self) -> None:
        if not self._scan_results:
            messagebox.showinfo("No results", "Run a scan first.")
            return

        default_name = f"temifi_audit_{time.strftime('%Y%m%d_%H%M%S')}.md"
        path = filedialog.asksaveasfilename(
            title="Export audit report (Markdown)",
            defaultextension=".md",
            initialfile=default_name,
            filetypes=[("Markdown", "*.md"), ("All files", "*.*")],
        )
        if not path:
            return

        best, counts = recommend_24ghz_channel(self._scan_results)

        lines: list[str] = []
        lines.append(f"# {main.NAME} Wi-Fi Audit Report")
        lines.append("")
        lines.append(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- Interface: {self._last_scan_iface or self.selected_iface.get() or '?'}")
        lines.append(f"- Networks parsed: {len(self._scan_results)}")
        lines.append("")

        if best is not None:
            lines.append(f"## Channel recommendation (2.4 GHz)")
            lines.append(f"- Recommended channel (among 1/6/11): **{best}**")
            lines.append("")
        lines.append("### Observed 2.4 GHz channel counts")
        lines.append("")
        lines.append("| Channel | APs |")
        lines.append("|---:|---:|")
        for ch in range(1, 14):
            lines.append(f"| {ch} | {counts.get(ch, 0)} |")
        lines.append("")

        lines.append("## Hardening checklist")
        lines.append("")
        lines.append("- Prefer **WPA3-SAE** (or WPA2/WPA3 mixed only if needed).")
        lines.append("- **Disable WPS**.")
        lines.append("- Use a long unique passphrase (16+ chars).")
        lines.append("- Update router firmware; disable legacy (WEP/WPA).")
        lines.append("- Separate guest/IoT SSIDs; enable guest isolation.")
        lines.append("")

        lines.append("## Nearby networks (from iw scan)")
        lines.append("")
        lines.append("| SSID | Security | Band | Ch | Freq (MHz) | Signal (dBm) | BSSID |")
        lines.append("|---|---|---:|---:|---:|---:|---|")
        for n in self._scan_results:
            ssid = str(n.get("ssid", "")).replace("|", "\\|")
            sec = str(n.get("security", "")).replace("|", "\\|")
            band = str(n.get("band", "")).replace("|", "\\|")
            ch = n.get("channel")
            freq = n.get("freq_mhz")
            sig = n.get("signal_dbm")
            bssid = str(n.get("bssid", "")).replace("|", "\\|")
            lines.append(
                f"| {ssid} | {sec} | {band} | {ch if ch is not None else ''} | "
                f"{freq if freq is not None else ''} | {sig if sig is not None else ''} | {bssid} |"
            )

        try:
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
            self._set_status(f"Exported report: {path}")
            self._log(f"Exported report: {path}")
        except Exception as e:
            self._log(f"Report export failed: {e}")
            messagebox.showerror("Export failed", str(e))

    # ---- services ----

    def restart_network_manager(self) -> None:
        self._set_status("Restarting NetworkManager…")
        self._log("Running: systemctl restart NetworkManager")

        def work():
            return subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True, text=True, check=False)

        def done(proc, err):
            if err:
                self._set_status("Restart failed.")
                self._log(f"Error: {err}")
                messagebox.showerror("Error", str(err))
                return

            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip() or "(no stderr)"
                self._set_status("Restart failed.")
                self._log(f"systemctl failed (code {proc.returncode}): {stderr}")
                messagebox.showerror("Restart failed", f"{stderr}\n\nTip: run as root (sudo).")
                return

            self._set_status("NetworkManager restarted.")
            self._log("NetworkManager restart requested successfully.")

        self._run_thread(work, on_done=done)

    # ---- misc ----

    def open_captures_dir(self) -> None:
        log_dir = getattr(main, "LOG_DIR", Path("captures"))
        try:
            Path(log_dir).mkdir(exist_ok=True)
        except Exception:
            pass

        opener = shutil.which("xdg-open")
        if not opener:
            messagebox.showinfo("Captures folder", f"Captures directory:\n{log_dir}")
            return

        self._log(f"Opening folder: {log_dir}")
        subprocess.run([opener, str(log_dir)], check=False)


def main_gui() -> None:
    root = Tk()
    try:
        root.call("tk", "scaling", 1.1)
    except Exception:
        pass
    TemifiGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main_gui()
