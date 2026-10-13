import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from centinela.engine import ScanEngine, system_root
from centinela.models import Finding, ScanReport, Severity, Threat
from centinela.quarantine import QuarantineVault
from centinela.remediation import plan_remediation
from centinela.scoring import aggregate

PALETTE = {
    "background": "#0d1012",
    "surface": "#151a1d",
    "raised": "#1d2428",
    "line": "#2a3338",
    "text": "#e8e3d9",
    "muted": "#8b969c",
    "signal": "#f0a43a",
    "high": "#ef5350",
    "medium": "#f0a43a",
    "low": "#7fb8a4",
}
FONT_DISPLAY = ("Bahnschrift SemiBold", 22)
FONT_COUNTER = ("Bahnschrift", 26)
FONT_TEXT = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO = ("Cascadia Mono", 10)
SEVERITY_LABELS = {Severity.HIGH: "Alto", Severity.MEDIUM: "Medio", Severity.LOW: "Bajo"}
COUNTER_LABELS = {Severity.HIGH: "Riesgo alto", Severity.MEDIUM: "Riesgo medio", Severity.LOW: "Riesgo bajo"}
MAX_ACTIONS_IN_DIALOG = 12


class CentinelaApp:
    def __init__(self, root: tk.Tk, engine: ScanEngine, vault: QuarantineVault, admin: bool):
        self._root = root
        self._engine = engine
        self._vault = vault
        self._events: queue.Queue = queue.Queue()
        self._scan_findings: list[Finding] = []
        self._watch_findings: list[Finding] = []
        self._threats: list[Threat] = []
        self._watch_stop: threading.Event | None = None
        self._busy = False
        self._configure_window()
        self._build_layout()
        self._set_status("Listo para escanear" if admin else "Sin permisos de administrador: el análisis será parcial")
        self._root.after(100, self._process_events)

    def _configure_window(self) -> None:
        self._root.title("Centinela")
        self._root.geometry("1180x760")
        self._root.minsize(860, 560)
        self._root.configure(background=PALETTE["background"])
        style = ttk.Style(self._root)
        style.theme_use("clam")
        style.configure(".", background=PALETTE["background"], foreground=PALETTE["text"], font=FONT_TEXT)
        style.configure("Surface.TFrame", background=PALETTE["surface"])
        style.configure("TButton", background=PALETTE["raised"], foreground=PALETTE["text"], bordercolor=PALETTE["line"],
                        focuscolor=PALETTE["signal"], padding=(16, 8), relief="flat")
        style.map("TButton", background=[("disabled", PALETTE["surface"]), ("active", PALETTE["line"])],
                  foreground=[("disabled", PALETTE["muted"])])
        style.configure("Signal.TButton", background=PALETTE["signal"], foreground=PALETTE["background"])
        style.map("Signal.TButton", background=[("disabled", PALETTE["surface"]), ("active", "#ffbb5c")])
        style.configure("Treeview", background=PALETTE["surface"], fieldbackground=PALETTE["surface"],
                        foreground=PALETTE["text"], bordercolor=PALETTE["line"], lightcolor=PALETTE["line"],
                        darkcolor=PALETTE["line"], borderwidth=1, rowheight=30, font=FONT_TEXT)
        style.map("Treeview", background=[("selected", PALETTE["raised"])], foreground=[("selected", PALETTE["signal"])])
        style.configure("Treeview.Heading", background=PALETTE["background"], foreground=PALETTE["muted"],
                        bordercolor=PALETTE["line"], relief="flat", font=FONT_SMALL, padding=(8, 6))
        style.configure("Vertical.TScrollbar", background=PALETTE["raised"], troughcolor=PALETTE["surface"],
                        bordercolor=PALETTE["surface"], lightcolor=PALETTE["raised"], darkcolor=PALETTE["raised"],
                        arrowcolor=PALETTE["muted"], gripcount=0)
        style.map("Vertical.TScrollbar", background=[("active", PALETTE["line"])])
        self._root.bind("<F5>", lambda _event: self._start_scan())

    def _build_layout(self) -> None:
        header = tk.Frame(self._root, background=PALETTE["background"], padx=28, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="CENTINELA", font=FONT_DISPLAY, foreground=PALETTE["signal"],
                 background=PALETTE["background"]).pack(side="left")
        self._status = tk.Label(header, font=FONT_TEXT, foreground=PALETTE["muted"], background=PALETTE["background"], anchor="e")
        self._status.pack(side="right", fill="x", expand=True)

        summary = tk.Frame(self._root, background=PALETTE["background"], padx=28)
        summary.pack(fill="x")
        self._counters = {}
        for severity, color in ((Severity.HIGH, "high"), (Severity.MEDIUM, "medium"), (Severity.LOW, "low")):
            cell = tk.Frame(summary, background=PALETTE["surface"], padx=18, pady=10,
                            highlightthickness=1, highlightbackground=PALETTE["line"])
            cell.pack(side="left", padx=(0, 12))
            counter = tk.Label(cell, text="0", font=FONT_COUNTER, foreground=PALETTE[color], background=PALETTE["surface"])
            counter.pack(anchor="w")
            tk.Label(cell, text=COUNTER_LABELS[severity], font=FONT_SMALL,
                     foreground=PALETTE["muted"], background=PALETTE["surface"]).pack(anchor="w")
            self._counters[severity] = counter

        toolbar = tk.Frame(self._root, background=PALETTE["background"], padx=28, pady=16)
        toolbar.pack(fill="x")
        self._scan_button = ttk.Button(toolbar, text="Escanear (F5)", style="Signal.TButton", command=self._start_scan)
        self._watch_button = ttk.Button(toolbar, text="Vigilar en vivo", command=self._toggle_watch)
        self._neutralize_button = ttk.Button(toolbar, text="Neutralizar selección", command=self._neutralize_selected)
        self._quarantine_button = ttk.Button(toolbar, text="Cuarentena", command=self._open_quarantine)
        self._export_button = ttk.Button(toolbar, text="Exportar informe", command=self._export_report)
        for button in (self._scan_button, self._watch_button, self._neutralize_button, self._quarantine_button, self._export_button):
            button.pack(side="left", padx=(0, 8))

        panes = tk.PanedWindow(self._root, orient="vertical", background=PALETTE["background"], sashwidth=6, borderwidth=0)
        panes.pack(fill="both", expand=True, padx=28, pady=(0, 24))
        table = tk.Frame(panes, background=PALETTE["surface"])
        self._tree = ttk.Treeview(table, columns=("score", "severity", "kind", "target"), show="headings", selectmode="extended")
        for column, title, width, stretch in (("score", "Puntaje", 80, False), ("severity", "Riesgo", 90, False),
                                              ("kind", "Tipo", 110, False), ("target", "Objetivo", 300, True)):
            self._tree.heading(column, text=title, anchor="w")
            self._tree.column(column, width=width, minwidth=width if not stretch else 200, stretch=stretch, anchor="w")
        for severity, color in ((Severity.HIGH, "high"), (Severity.MEDIUM, "medium"), (Severity.LOW, "low")):
            self._tree.tag_configure(severity.value, foreground=PALETTE[color])
        scrollbar = ttk.Scrollbar(table, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._tree.pack(side="left", fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", lambda _event: self._show_details())
        panes.add(table, minsize=200, stretch="always")

        self._details = tk.Text(panes, height=10, wrap="word", font=FONT_MONO, background=PALETTE["surface"],
                                foreground=PALETTE["text"], insertbackground=PALETTE["text"], relief="flat",
                                padx=16, pady=12, highlightthickness=1, highlightbackground=PALETTE["line"],
                                highlightcolor=PALETTE["signal"])
        self._details.configure(state="disabled")
        panes.add(self._details, minsize=120)

    def _set_status(self, text: str) -> None:
        self._status.configure(text=text)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = ["disabled"] if busy else ["!disabled"]
        for button in (self._scan_button, self._neutralize_button, self._quarantine_button):
            button.state(state)

    def _start_scan(self) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self._run_in_background(lambda: ("scan_done", self._engine.scan(lambda text: self._events.put(("progress", text)))))

    def _run_in_background(self, work) -> None:
        def runner():
            try:
                self._events.put(work())
            except Exception as error:
                self._events.put(("failed", str(error)))
        threading.Thread(target=runner, daemon=True).start()

    def _toggle_watch(self) -> None:
        if self._watch_stop is not None:
            self._watch_stop.set()
            self._watch_stop = None
            self._watch_button.configure(text="Vigilar en vivo")
            self._set_status("Vigilancia detenida")
            return
        self._watch_stop = threading.Event()
        stop = self._watch_stop
        self._watch_button.configure(text="Detener vigilancia")
        self._set_status("Vigilando: abre el Administrador de tareas para cazar procesos que se esconden")
        threading.Thread(
            target=self._engine.watch, args=(stop, lambda findings: self._events.put(("watch", findings))), daemon=True,
        ).start()

    def _process_events(self) -> None:
        try:
            self._drain_events()
        finally:
            self._root.after(100, self._process_events)

    def _drain_events(self) -> None:
        while not self._events.empty():
            kind, payload = self._events.get_nowait()
            if kind == "progress":
                self._set_status(payload)
            elif kind == "scan_done":
                self._on_scan_done(payload)
            elif kind == "watch":
                self._watch_findings.extend(payload)
                self._refresh_threats()
                self._set_status(f"Vigilancia: {len(payload)} comportamiento(s) sospechoso(s) detectado(s)")
            elif kind == "remediation_done":
                self._on_remediation_done(*payload)
            elif kind == "failed":
                self._set_busy(False)
                self._set_status("La operación falló")
                messagebox.showerror("Centinela", payload)

    def _on_scan_done(self, report: ScanReport) -> None:
        self._set_busy(False)
        self._scan_findings = report.findings
        self._refresh_threats()
        self._set_status(f"Escaneo completo en {report.duration_seconds:.0f} s: {len(self._threats)} elemento(s) para revisar")
        if report.errors:
            messagebox.showwarning("Centinela", "Partes del sistema no se pudieron revisar:\n\n" + "\n".join(report.errors))

    def _refresh_threats(self) -> None:
        self._threats = aggregate(self._scan_findings + self._watch_findings)
        self._tree.delete(*self._tree.get_children())
        for index, threat in enumerate(self._threats):
            self._tree.insert("", "end", iid=str(index), tags=(threat.severity.value,), values=(
                threat.score, SEVERITY_LABELS[threat.severity], threat.target.kind.value, threat.target.label,
            ))
        for severity, counter in self._counters.items():
            counter.configure(text=str(sum(threat.severity is severity for threat in self._threats)))
        self._show_details()

    def _selected_threats(self) -> list[Threat]:
        return [self._threats[int(iid)] for iid in self._tree.selection()]

    def _show_details(self) -> None:
        selected = self._selected_threats()
        lines = []
        if selected:
            threat = selected[0]
            target = threat.target
            lines.append(target.label)
            if target.path:
                lines.append(f"Ruta: {target.path}")
            if target.pid is not None:
                lines.append(f"PID: {target.pid}")
            lines.append(f"Riesgo: {SEVERITY_LABELS[threat.severity]} ({threat.score}/100)")
            lines.append("")
            lines.append("Por qué:")
            lines.extend(f"  - {reason}" for reason in threat.reasons)
            actions = plan_remediation(threat, system_root())
            lines.append("")
            lines.append("Al neutralizar:" if actions else "Requiere revisión manual.")
            lines.extend(f"  - {action.description}" for action in actions)
        else:
            lines.append("Selecciona un elemento para ver por qué es sospechoso.")
        self._details.configure(state="normal")
        self._details.delete("1.0", "end")
        self._details.insert("1.0", "\n".join(lines))
        self._details.configure(state="disabled")

    def _neutralize_selected(self) -> None:
        threats = self._selected_threats()
        plans = [(threat, plan_remediation(threat, system_root())) for threat in threats]
        actions = [action for _, plan in plans for action in plan]
        if not actions:
            messagebox.showinfo("Centinela", "Selecciona elementos que tengan acciones disponibles.")
            return
        listed = "\n".join(f"- {action.description}" for action in actions[:MAX_ACTIONS_IN_DIALOG])
        remaining = len(actions) - MAX_ACTIONS_IN_DIALOG
        if remaining > 0:
            listed += f"\n... y {remaining} acción(es) más"
        if not messagebox.askyesno("Confirmar", f"Se harán estos cambios (se pueden deshacer desde Cuarentena):\n\n{listed}"):
            return
        self._set_busy(True)
        self._set_status("Neutralizando")
        self._run_in_background(lambda: ("remediation_done", self._execute_plans(plans)))

    def _execute_plans(self, plans) -> tuple[set, list[str]]:
        handled, errors = set(), []
        for threat, plan in plans:
            failed = False
            for action in plan:
                try:
                    self._vault.execute(action)
                except Exception as error:
                    failed = True
                    errors.append(f"{action.description}: {error}")
            if plan and not failed:
                handled.add(threat.target.key)
        return handled, errors

    def _on_remediation_done(self, handled: set, errors: list[str]) -> None:
        self._set_busy(False)
        self._scan_findings = [finding for finding in self._scan_findings if finding.target.key not in handled]
        self._watch_findings = [finding for finding in self._watch_findings if finding.target.key not in handled]
        self._refresh_threats()
        self._set_status(f"{len(handled)} elemento(s) neutralizado(s). Vuelve a escanear para confirmar.")
        if errors:
            messagebox.showwarning("Centinela", "Algunas acciones fallaron:\n\n" + "\n".join(errors))

    def _open_quarantine(self) -> None:
        window = tk.Toplevel(self._root, background=PALETTE["background"], padx=20, pady=20)
        window.title("Cuarentena")
        window.geometry("900x460")
        window.transient(self._root)
        tree = ttk.Treeview(window, columns=("created", "description", "state"), show="headings", selectmode="browse")
        for column, title, width in (("created", "Fecha", 160), ("description", "Acción", 560), ("state", "Estado", 120)):
            tree.heading(column, text=title, anchor="w")
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        def reload():
            tree.delete(*tree.get_children())
            for record in reversed(self._vault.records()):
                state = "Restaurado" if record.restored else ("Activo" if record.restorable else "Sin deshacer")
                tree.insert("", "end", iid=record.id, values=(record.created.replace("T", " "), record.description, state))

        def restore():
            selection = tree.selection()
            if not selection or not messagebox.askyesno("Confirmar", "¿Deshacer esta acción?", parent=window):
                return
            try:
                self._vault.restore(selection[0])
            except Exception as error:
                messagebox.showerror("Centinela", str(error), parent=window)
            reload()

        ttk.Button(window, text="Restaurar seleccionado", command=restore).pack(anchor="e", pady=(12, 0))
        reload()

    def _export_report(self) -> None:
        if not self._threats:
            messagebox.showinfo("Centinela", "No hay resultados para exportar.")
            return
        destination = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")],
                                                   initialfile="informe-centinela.json")
        if not destination:
            return
        report = [{
            "objetivo": threat.target.label,
            "tipo": threat.target.kind.value,
            "ruta": threat.target.path,
            "pid": threat.target.pid,
            "puntaje": threat.score,
            "riesgo": threat.severity.value,
            "motivos": threat.reasons,
        } for threat in self._threats]
        try:
            with open(destination, "w", encoding="utf-8") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
        except OSError as error:
            messagebox.showerror("Centinela", f"No se pudo guardar el informe: {error}")
            return
        self._set_status(f"Informe guardado en {destination}")


def run_gui(engine: ScanEngine, vault: QuarantineVault, admin: bool) -> None:
    root = tk.Tk()
    CentinelaApp(root, engine, vault, admin)
    root.mainloop()
