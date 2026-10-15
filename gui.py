#!/usr/bin/env python3
"""
gui.py — Threaded CustomTkinter Desktop Console for AEGIS SENTINEL v5.2.0.
"""

from __future__ import annotations

import json
import queue
import threading
from tkinter import filedialog, messagebox
from typing import Any, Dict

from config import CONFIG, ENGINE_VERSION
from scanner import AegisSentinelScanner

try:
    import customtkinter as ctk  # type: ignore
    CTK_AVAILABLE = True
except ImportError:  # pragma: no cover
    ctk = None
    CTK_AVAILABLE = False


class AegisSentinelGUI:
    def __init__(self) -> None:
        if not CTK_AVAILABLE or ctk is None:
            raise RuntimeError("CustomTkinter is required for GUI mode (pip install customtkinter).")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title(f"AEGIS SENTINEL — Autonomous XDR & MailGuard Console ({ENGINE_VERSION})")
        self.root.geometry("1080x720")

        self.scanner = AegisSentinelScanner(CONFIG)
        self.ui_queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self.cancel_event = threading.Event()

        self._build_layout()
        self.root.after(150, self._poll_queue)

    def _build_layout(self) -> None:
        header = ctk.CTkFrame(self.root, height=60)
        header.pack(fill="x", padx=12, pady=8)

        title_lbl = ctk.CTkLabel(
            header,
            text=f"AEGIS SENTINEL v5.2.0  |  Integrity: {self.scanner.integrity_report.get('status', 'OK').upper()}  |  LLM: {self.scanner._llm_posture_label()}",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        title_lbl.pack(side="left", padx=14, pady=12)

        controls = ctk.CTkFrame(self.root)
        controls.pack(fill="x", padx=12, pady=6)

        ctk.CTkButton(controls, text="Scan Single File / Email", command=self._on_scan_file).pack(side="left", padx=6, pady=8)
        ctk.CTkButton(controls, text="Scan Directory", command=self._on_scan_dir).pack(side="left", padx=6, pady=8)
        ctk.CTkButton(controls, text="Deploy Canaries", command=self._on_deploy_canaries).pack(side="left", padx=6, pady=8)
        ctk.CTkButton(controls, text="Verify Canaries", command=self._on_verify_canaries).pack(side="left", padx=6, pady=8)
        ctk.CTkButton(controls, text="Quarantine Vault", command=self._on_list_quarantine).pack(side="left", padx=6, pady=8)
        ctk.CTkButton(controls, text="Cancel Scan", fg_color="#8B0000", command=self._on_cancel).pack(side="right", padx=6, pady=8)

        self.progress = ctk.CTkProgressBar(self.root)
        self.progress.pack(fill="x", padx=12, pady=4)
        self.progress.set(0.0)

        self.output_box = ctk.CTkTextbox(self.root, font=ctk.CTkFont(family="Courier", size=13))
        self.output_box.pack(fill="both", expand=True, padx=12, pady=8)
        self._append_text(f"[+] AEGIS SENTINEL {ENGINE_VERSION} Ready.\n[+] Active Layers: {self.scanner._active_layers_label()}\n\n")

    def _append_text(self, text: str) -> None:
        self.output_box.insert("end", text)
        self.output_box.see("end")

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self.ui_queue.get_nowait()
                kind = msg.get("kind")
                if kind == "log":
                    self._append_text(str(msg.get("text", "")) + "\n")
                elif kind == "progress":
                    self.progress.set(float(msg.get("value", 0.0)))
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def _on_scan_file(self) -> None:
        path = filedialog.askopenfilename(title="Select Artifact or Email to Scan")
        if not path:
            return
        self.cancel_event.clear()
        self.progress.set(0.1)

        def _worker() -> None:
            res = self.scanner.scan_file(path)
            rep = self.scanner.generate_report([res])
            self.ui_queue.put({"kind": "progress", "value": 1.0})
            self.ui_queue.put({"kind": "log", "text": rep})

        threading.Thread(target=_worker, daemon=True).start()

    def _on_scan_dir(self) -> None:
        folder = filedialog.askdirectory(title="Select Directory to Scan")
        if not folder:
            return
        self.cancel_event.clear()
        self.progress.set(0.0)

        def _prog(done: int, total: int, path: str, res: Dict[str, Any]) -> None:
            ratio = done / max(1, total)
            self.ui_queue.put({"kind": "progress", "value": ratio})
            self.ui_queue.put({"kind": "log", "text": f"[{done}/{total}] {path} -> {res.get('verdict')} ({res.get('risk_score')}/100)"})

        def _worker() -> None:
            results = self.scanner.scan_directory(folder, progress_callback=_prog, cancel_event=self.cancel_event)
            rep = self.scanner.generate_report(results)
            self.ui_queue.put({"kind": "log", "text": rep})

        threading.Thread(target=_worker, daemon=True).start()

    def _on_deploy_canaries(self) -> None:
        dep = self.scanner.canary_manager.deploy_canaries(self.scanner.scan_dirs)
        self._append_text(f"[Canary] Deployed {len(dep)} decoy file(s):\n{json.dumps(dep, indent=2)}\n")

    def _on_verify_canaries(self) -> None:
        rep = self.scanner.canary_manager.verify_canaries()
        self._append_text(f"[Canary Audit]\n{json.dumps(rep.as_dict(), indent=2)}\n")

    def _on_list_quarantine(self) -> None:
        items = self.scanner.quarantine_manager.list_quarantine()
        self._append_text(f"[Quarantine Vault ({len(items)} item(s))]\n{json.dumps(items, indent=2)}\n")

    def _on_cancel(self) -> None:
        self.cancel_event.set()
        self._append_text("[!] Scan cancellation requested.\n")

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = AegisSentinelGUI()
    app.run()


if __name__ == "__main__":
    main()