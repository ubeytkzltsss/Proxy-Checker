"""A small Turkish GUI for checking user-provided SOCKS5 proxies."""

from __future__ import annotations

import concurrent.futures
import csv
import json
import queue
import re
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import quote, urlsplit

try:
    import requests  # Optional; enables SOCKS proxies when requests[socks] is installed.
except ImportError:
    requests = None


DEFAULT_CHECK_URL = "https://api.ipify.org"
USER_AGENT = "ProxyChecker/1.0"
MAX_PROXIES_PER_RUN = 2000


@dataclass(frozen=True)
class ProxyResult:
    proxy: str
    working: bool
    latency_ms: int
    exit_ip: str
    message: str


def _dict_proxy_value(item: dict) -> str | None:
    """Convert a common JSON proxy object (host/ip + port) to a proxy URL."""
    lowered = {str(key).casefold(): value for key, value in item.items()}
    host = next((lowered[key] for key in ("host", "ip", "address", "server") if lowered.get(key)), None)
    port = lowered.get("port")

    # Some formats store a complete proxy URL in a field named "proxy".
    proxy_field = lowered.get("proxy")
    if isinstance(proxy_field, str) and proxy_field.strip():
        return proxy_field.strip()
    if not host:
        return None
    host = str(host).strip()
    if "://" in host:
        return host
    if port in (None, "") and ":" in host:
        return host
    if port in (None, ""):
        return None

    scheme = str(lowered.get("protocol") or lowered.get("scheme") or lowered.get("type") or "auto").strip().lower()
    scheme = scheme.removesuffix(":")
    if not scheme:
        scheme = "auto"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6 literal

    username = lowered.get("username", lowered.get("user"))
    password = lowered.get("password", lowered.get("pass"))
    auth = ""
    if username is not None and str(username) != "":
        auth = quote(str(username), safe="")
        if password is not None:
            auth += ":" + quote(str(password), safe="")
        auth += "@"
    return f"{scheme}://{auth}{host}:{port}"


def _collect_json_candidates(value) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if value.strip():
            found.append(value.strip())
    elif isinstance(value, list):
        for entry in value:
            found.extend(_collect_json_candidates(entry))
    elif isinstance(value, dict):
        candidate = _dict_proxy_value(value)
        if candidate:
            found.append(candidate)
        # Traverse containers too, to support wrappers like {"data": {"proxies": [...]}}.
        for key, entry in value.items():
            if str(key).casefold() not in {"host", "ip", "address", "server", "port", "username", "user", "password", "pass"}:
                found.extend(_collect_json_candidates(entry))
    return found


def _normalize_proxy(candidate: str) -> str:
    value = candidate.strip()
    if not value:
        raise ValueError("Boş proxy kaydı")

    # Common text format: host:port:username:password
    if "://" not in value and "@" not in value:
        parts = value.split(":")
        if len(parts) == 4 and parts[1].isdigit():
            host, port, username, password = parts
            value = f"auto://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        else:
            value = "auto://" + value

    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("Adres biçimi tanınmadı")
    if parsed.scheme.casefold() not in {"auto", "http", "https", "socks4", "socks5", "socks5h"}:
        raise ValueError(f"Desteklenmeyen protokol: {parsed.scheme}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Port numarası geçersiz") from exc
    if port is None or not (1 <= port <= 65535):
        raise ValueError("Port 1–65535 arasında olmalı")
    return value


def load_proxy_file(path: str) -> list[str]:
    file_path = Path(path)
    raw_text = None
    for encoding in ("utf-8-sig", "utf-8", "cp1254", "latin-1"):
        try:
            raw_text = file_path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue
    if raw_text is None:
        raise ValueError("Dosyanın karakter kodlaması okunamadı.")

    if file_path.suffix.casefold() == ".json":
        try:
            candidates = _collect_json_candidates(json.loads(raw_text))
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON dosyası çözümlenemedi: {exc}") from exc
    else:
        candidates = []
        for line in raw_text.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", ";")):
                candidates.extend(_extract_text_candidates(line))

    proxies: list[str] = []
    seen: set[str] = set()
    rejected = 0
    for candidate in candidates:
        try:
            normalized = _normalize_proxy(candidate)
        except ValueError:
            rejected += 1
            continue
        if normalized not in seen:
            seen.add(normalized)
            proxies.append(normalized)
    if not proxies:
        detail = f" ({rejected} satır tanınmadı)" if rejected else ""
        raise ValueError("Dosyada tanınan proxy bulunamadı." + detail)
    if len(proxies) > MAX_PROXIES_PER_RUN:
        raise ValueError(f"Bu sürümde tek çalıştırmada en fazla {MAX_PROXIES_PER_RUN} proxy kontrol edilebilir. Dosyayı daha küçük parçalara ayırın.")
    return proxies


def _extract_text_candidates(line: str) -> list[str]:
    """Extract an address from plain text or a copied proxy-table row."""
    stripped = line.strip()
    if "://" in stripped:
        return [stripped.split()[0]]
    match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}(?!\d)", stripped)
    if not match:
        return [stripped]
    address = match.group(0)
    protocol_match = re.search(r"\b(SOCKS5H?|SOCKS4|HTTPS?|HTTP)\b", stripped, re.IGNORECASE)
    if protocol_match:
        return [f"{protocol_match.group(1).lower()}://{address}"]
    return [address]


def _extract_ip(body: str) -> str:
    text = body.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            for key in ("ip", "origin", "query"):
                if parsed.get(key):
                    return str(parsed[key]).strip()[:100]
    except (json.JSONDecodeError, TypeError):
        pass
    if text and len(text) <= 100 and "\n" not in text:
        return text
    return "—"


def check_proxy(proxy: str, check_url: str, timeout: float) -> ProxyResult:
    start = time.perf_counter()
    parsed = urlsplit(proxy)
    scheme = parsed.scheme.casefold()
    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain, application/json, */*"}
    protocols = ["socks5", "socks4", "http", "https"] if scheme == "auto" else [scheme]
    last_error = "Bağlantı kurulamadı"
    try:
        if requests is None:
            raise RuntimeError("Proxy desteği için requests[socks] kurulmalı: pip install \"requests[socks]\"")
        with requests.Session() as session:
            session.trust_env = False
            for protocol in protocols:
                candidate = parsed._replace(scheme=protocol).geturl()
                try:
                    response = session.get(
                        check_url,
                        proxies={"http": candidate, "https": candidate},
                        timeout=(timeout, timeout),
                        headers=headers,
                    )
                    response.raise_for_status()
                    body = response.text[:2048]
                    elapsed = int((time.perf_counter() - start) * 1000)
                    return ProxyResult(candidate, True, elapsed, _extract_ip(body), f"Bağlantı başarılı ({protocol.upper()})")
                except Exception as exc:
                    last_error = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
                    last_error = re.sub(r"(?i)(https?|socks\w*)://[^/@\s]+@", r"\1://***@", last_error)
        elapsed = int((time.perf_counter() - start) * 1000)
        tried = ", ".join(protocol.upper() for protocol in protocols)
        return ProxyResult(proxy, False, elapsed, "—", f"{tried} denendi: {last_error[:140]}")
    except Exception as exc:  # Network errors vary by proxy and operating system.
        elapsed = int((time.perf_counter() - start) * 1000)
        message = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        # Avoid displaying credentials if a network library includes the proxy URL in its error.
        message = re.sub(r"(?i)(https?|socks\w*)://[^/@\s]+@", r"\1://***@", message)
        return ProxyResult(proxy, False, elapsed, "—", message[:180])


def _masked_proxy(proxy: str) -> str:
    if "@" not in proxy:
        return proxy
    scheme, rest = proxy.split("://", 1) if "://" in proxy else ("http", proxy)
    userinfo, host = rest.rsplit("@", 1)
    username = userinfo.split(":", 1)[0]
    return f"{scheme}://{username}:***@{host}"


class ProxyCheckerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOCKS5 Proxy Checker")
        self.root.geometry("1040x650")
        self.root.minsize(820, 500)
        self.file_path = tk.StringVar()
        self.check_url = tk.StringVar(value=DEFAULT_CHECK_URL)
        self.timeout = tk.StringVar(value="8")
        self.workers = tk.StringVar(value="20")
        self.progress_text = tk.StringVar(value="Kontrol için bir TXT veya JSON dosyası seçin.")
        self.results: list[ProxyResult] = []
        self.events: queue.Queue = queue.Queue()
        self.running = False

        self._build_ui()
        self.root.after(100, self._poll_events)

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(1, weight=1)
        outer.rowconfigure(5, weight=1)

        ttk.Label(outer, text="Proxy dosyası:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(outer, textvariable=self.file_path).grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Button(outer, text="Dosya seç…", command=self._choose_file).grid(row=0, column=2, padx=(8, 0), pady=5)

        ttk.Label(outer, text="Kontrol adresi:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(outer, textvariable=self.check_url).grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Label(outer, text="Varsayılan: api.ipify.org").grid(row=1, column=2, sticky="w", padx=(8, 0), pady=5)

        settings = ttk.Frame(outer)
        settings.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(3, 8))
        ttk.Label(settings, text="Timeout (sn):").pack(side="left")
        ttk.Spinbox(settings, from_=1, to=60, width=5, textvariable=self.timeout).pack(side="left", padx=(6, 18))
        ttk.Label(settings, text="Eşzamanlı kontrol:").pack(side="left")
        ttk.Spinbox(settings, from_=1, to=100, width=5, textvariable=self.workers).pack(side="left", padx=6)
        self.start_button = ttk.Button(settings, text="Kontrolü başlat", command=self._start)
        self.start_button.pack(side="left", padx=(12, 5))
        self.csv_button = ttk.Button(settings, text="Sonuçları CSV kaydet…", command=self._save_csv, state="disabled")
        self.csv_button.pack(side="left", padx=5)
        self.txt_button = ttk.Button(settings, text="Çalışanları TXT kaydet…", command=self._save_working, state="disabled")
        self.txt_button.pack(side="left", padx=5)

        ttk.Label(outer, textvariable=self.progress_text).grid(row=3, column=0, columnspan=3, sticky="w", pady=(0, 5))
        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 8))

        columns = ("proxy", "status", "latency", "ip", "message")
        self.table = ttk.Treeview(outer, columns=columns, show="headings")
        headings = {"proxy": "Proxy", "status": "Durum", "latency": "Süre (ms)", "ip": "Çıkış IP", "message": "Açıklama"}
        widths = {"proxy": 300, "status": 105, "latency": 85, "ip": 135, "message": 280}
        for column in columns:
            self.table.heading(column, text=headings[column])
            self.table.column(column, width=widths[column], minwidth=70, anchor="w")
        self.table.tag_configure("working", foreground="#087a32")
        self.table.tag_configure("failed", foreground="#a12622")
        scroll_y = ttk.Scrollbar(outer, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(outer, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.table.grid(row=5, column=0, columnspan=2, sticky="nsew")
        scroll_y.grid(row=5, column=2, sticky="ns")
        scroll_x.grid(row=6, column=0, columnspan=3, sticky="ew")

        ttk.Label(
            outer,
            text="Şema yazıyorsa (ör. socks5://) onu kullanır. Şemasız IP:PORT kayıtlarında SOCKS5 → SOCKS4 → HTTP → HTTPS sırasıyla denenir. Çalışan proxy, algılanan şemasıyla gösterilip kaydedilir. Tek çalıştırma en fazla 1000 kayıt alır.",
            wraplength=950,
        ).grid(row=7, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _choose_file(self):
        path = filedialog.askopenfilename(
            title="Proxy dosyası seç",
            filetypes=[("Proxy dosyaları", "*.txt *.json"), ("Tüm dosyalar", "*.*")],
        )
        if path:
            self.file_path.set(path)

    def _start(self):
        path = self.file_path.get().strip()
        if not path:
            messagebox.showwarning("Dosya seçilmedi", "Önce bir TXT veya JSON dosyası seçin.")
            return
        parsed_url = urlsplit(self.check_url.get().strip())
        if parsed_url.scheme.casefold() not in {"http", "https"} or not parsed_url.hostname:
            messagebox.showerror("Adres hatalı", "Kontrol adresi http:// veya https:// ile başlamalı.")
            return
        try:
            timeout = float(self.timeout.get())
            workers = int(self.workers.get())
            if not 1 <= timeout <= 60 or not 1 <= workers <= 100:
                raise ValueError
            proxies = load_proxy_file(path)
        except ValueError as exc:
            messagebox.showerror("Ayarlar veya dosya hatalı", str(exc) or "Timeout 1–60, eşzamanlı kontrol 1–100 arasında olmalı.")
            return
        except OSError as exc:
            messagebox.showerror("Dosya açılamadı", str(exc))
            return

        self.results.clear()
        for item in self.table.get_children():
            self.table.delete(item)
        self.progress.configure(maximum=len(proxies), value=0)
        self.progress_text.set(f"0/{len(proxies)} kontrol edildi…")
        self.running = True
        self.start_button.configure(state="disabled")
        self.csv_button.configure(state="disabled")
        self.txt_button.configure(state="disabled")
        thread = threading.Thread(
            target=self._check_all,
            args=(proxies, self.check_url.get().strip(), timeout, workers),
            daemon=True,
        )
        thread.start()

    def _check_all(self, proxies: list[str], check_url: str, timeout: float, workers: int):
        completed = 0
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(check_proxy, proxy, check_url, timeout) for proxy in proxies]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = ProxyResult("(bilinmeyen)", False, 0, "—", str(exc)[:180])
                    completed += 1
                    self.events.put(("result", result, completed, len(proxies)))
        except Exception as exc:
            self.events.put(("fatal", str(exc)))
        finally:
            self.events.put(("done",))

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "result":
                    _, result, completed, total = event
                    self.results.append(result)
                    status = "Çalışıyor" if result.working else "Çalışmıyor"
                    tag = "working" if result.working else "failed"
                    self.table.insert(
                        "", "end",
                        values=(_masked_proxy(result.proxy), status, result.latency_ms, result.exit_ip, result.message),
                        tags=(tag,),
                    )
                    working = sum(item.working for item in self.results)
                    self.progress.configure(value=completed)
                    self.progress_text.set(f"{completed}/{total} kontrol edildi  •  Çalışan: {working}  •  Çalışmayan: {completed - working}")
                elif event[0] == "fatal":
                    messagebox.showerror("Kontrol hatası", event[1])
                elif event[0] == "done":
                    self.running = False
                    self.start_button.configure(state="normal")
                    self.csv_button.configure(state="normal" if self.results else "disabled")
                    self.txt_button.configure(state="normal" if any(item.working for item in self.results) else "disabled")
                    self.progress_text.set(
                        f"Tamamlandı  •  Çalışan: {sum(item.working for item in self.results)}  •  Çalışmayan: {sum(not item.working for item in self.results)}"
                    )
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _save_csv(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title="Sonuçları CSV kaydet",
            defaultextension=".csv",
            initialfile="proxy-sonuclari.csv",
            filetypes=[("CSV dosyası", "*.csv")],
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["proxy", "durum", "sure_ms", "cikis_ip", "aciklama"])
            for result in self.results:
                writer.writerow([result.proxy, "çalışıyor" if result.working else "çalışmıyor", result.latency_ms, result.exit_ip, result.message])
        messagebox.showinfo("Kaydedildi", f"CSV dosyası kaydedildi:\n{path}")

    def _save_working(self):
        working = [result.proxy for result in self.results if result.working]
        if not working:
            return
        path = filedialog.asksaveasfilename(
            title="Çalışan proxy'leri TXT kaydet",
            defaultextension=".txt",
            initialfile="calisan-proxyler.txt",
            filetypes=[("Metin dosyası", "*.txt")],
        )
        if not path:
            return
        Path(path).write_text("\n".join(working) + "\n", encoding="utf-8")
        messagebox.showinfo("Kaydedildi", f"{len(working)} çalışan proxy kaydedildi:\n{path}")


def main():
    root = tk.Tk()
    ProxyCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
