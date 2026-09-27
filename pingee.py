"""pingee: a desktop application for continuous, multi-target network monitoring.

The program combines four layers in one dependency-light Tkinter application:

* Parsers normalize pasted host inventories, Linux neighbor tables, network
  interfaces, and verbose tcpdump DHCP output into small Python data records.
* Background workers run local ICMP probes, persistent SSH-based probes,
  neighbor-table polling, and streamed DHCP capture. Workers never manipulate
  Tk widgets; they publish immutable-ish event tuples through a thread-safe
  queue for the GUI thread to consume.
* :class:`PingeeApp` owns application state, translates events into
  in-memory histories, and refreshes the visible tables and graphs.
* The presentation layer supports detachable views, target filters, sortable
  tables, time-window selection, graph tooltips, CSV import/export, and six UI
  languages (English is the default).

Concurrency model
-----------------
Each target has an independent :class:`PingWorker`. Local workers use a
bounded semaphore to limit concurrently running operating-system ping
processes. SSH workers submit asynchronous requests to :class:`SSHRemote`,
which multiplexes many probes over a small number of long-lived shell
channels. The TCP/IP stack and remote command remain responsible for actual
ICMP timing; the GUI receives a completion event as soon as each probe ends.

The GUI polls the event queue on Tk's main thread. All widget reads and writes,
including dialogs and graph redraws, belong on that thread. Worker threads may
only communicate with the UI by enqueueing events. This rule prevents the
intermittent Tcl/Tk failures that occur when widgets are touched from workers.

Data lifetime and limits
------------------------
Probe results, DHCP packets, and neighbor observations are held in memory
until the application exits or the user exports them. Per-target graph data is
bounded by :data:`MAX_POINTS`; neighbor snapshot/observation histories are
bounded by :data:`MAX_NEIGHBOR_HISTORY`. The number of configured targets is
not artificially capped, although system resources and probe concurrency
settings naturally limit practical throughput.

Security and platform notes
---------------------------
SSH support is optional and uses Paramiko when installed. Credentials stay in
process memory for the session. The first host key is accepted for that
session, rather than written to a persistent known-hosts file; deployments
that require strict host identity verification should adapt
:meth:`SSHRemote._get_client`. Local ping command-line flags vary by operating
system and are selected at runtime. Remote commands assume a Unix-like SSH
host with ``ping``, ``ip`` (or ``arp``), and optionally ``tcpdump`` available.

This module is also the executable entry point. Running ``python pingee.py``
constructs the Tk root and starts the event loop via :func:`main`.
"""

from __future__ import annotations

# Copyright (C) 2026 Max Petermann
# SPDX-License-Identifier: GPL-3.0-or-later

import csv
import ipaddress
import os
import platform
import queue
import re
import subprocess
import threading
import time
import tkinter as tk
from collections import defaultdict, deque
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "pingee · Network Monitor"
# Defaults and retention caps used by the probe scheduler and in-memory stores.
DEFAULT_INTERVAL = 1.0
MAX_POINTS = 100_000
# Patterns shared by target parsing, hostname detection, and MAC lookup.
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HOST_RE = re.compile(r"(?<![@\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w.-])")
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")
MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
NEIGHBOR_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT", "NOARP", "NONE"}
MAX_NEIGHBOR_HISTORY = 200_000

# Translation tuples always use this order: EN, DE, ES, NL, PL, CN.
LANGUAGE_CHOICES = ("EN", "DE", "ES", "NL", "PL", "CN")
LANGUAGE_NAMES = {"EN": "English", "DE": "Deutsch", "ES": "Español", "NL": "Nederlands", "PL": "Polski", "CN": "中文"}

# (English, Deutsch, Español, Nederlands, Polski, 中文); source keys match the original German UI.
# Keep static widget labels here. Use STATUS_TRANSLATIONS for messages that
# need runtime values such as host names, counts, or elapsed times.
TRANSLATIONS = {
    "Netzwerkmonitor": ("Network monitor", "Netzwerkmonitor", "Monitor de red", "Netwerkmonitor", "Monitor sieci", "网络监视器"),
    "Netzwerkmonitor · DHCP tcpdump": ("pingee · DHCP capture", "pingee · DHCP tcpdump", "pingee · Captura DHCP", "pingee · DHCP-opname", "pingee · Przechwytywanie DHCP", "pingee · DHCP 捕获"),
    "Netzwerkmonitor · ARP / ip neigh": ("pingee · ARP / ip neigh", "pingee · ARP / ip neigh", "pingee · ARP / ip neigh", "pingee · ARP / ip neigh", "pingee · ARP / ip neigh", "pingee · ARP / ip neigh"),
    "pingee · Ziele": ("pingee · Targets", "pingee · Ziele", "pingee · Destinos", "pingee · Doelen", "pingee · Cele", "pingee · 目标"),
    "pingee · Messwerte im Arbeitsspeicher": ("pingee · Measurements in memory", "pingee · Messwerte im Arbeitsspeicher", "pingee · Mediciones en memoria", "pingee · Metingen in geheugen", "pingee · Pomiary w pamięci", "pingee · 内存测量数据"),
    "pingee · Latenzverlauf": ("pingee · Latency history", "pingee · Latenzverlauf", "pingee · Historial de latencia", "pingee · Latentiegeschiedenis", "pingee · Historia opóźnień", "pingee · 延迟历史"),
    "Kontinuierliche Latenz- und Erreichbarkeitsmessung · mehrere Ziele parallel": ("Continuous latency and availability monitoring · multiple targets in parallel", "Kontinuierliche Latenz- und Erreichbarkeitsmessung · mehrere Ziele parallel", "Supervisión continua de latencia y disponibilidad · varios destinos en paralelo", "Continue latentie- en beschikbaarheidsmeting · meerdere doelen parallel", "Ciągły pomiar opóźnień i dostępności · wiele celów równolegle", "持续监测延迟和可用性 · 并行监控多个目标"),
    "Messparameter": ("Probe settings", "Messparameter", "Parámetros de medición", "Meetinstellingen", "Ustawienia pomiaru", "测量参数"),
    "SSH": ("SSH", "SSH", "SSH", "SSH", "SSH", "SSH"), "Filter": ("Filters", "Filter", "Filtros", "Filters", "Filtry", "筛选"),
    "Import / Export": ("Import / Export", "Import / Export", "Importar / Exportar", "Importeren / Exporteren", "Import / Eksport", "导入 / 导出"),
    "Fenster": ("Windows", "Fenster", "Ventanas", "Vensters", "Okna", "窗口"),
    "Ziele": ("Targets", "Ziele", "Destinos", "Doelen", "Cele", "目标"), "Graph": ("Graph", "Graph", "Gráfico", "Grafiek", "Wykres", "图表"), "Messwerte": ("Measurements", "Messwerte", "Mediciones", "Metingen", "Pomiary", "测量值"),
    "Language": ("Language", "Sprache", "Idioma", "Taal", "Język", "语言"),
    "Messung starten": ("Start monitoring", "Messung starten", "Iniciar medición", "Meting starten", "Rozpocznij pomiar", "开始监测"),
    "Messung stoppen": ("Stop monitoring", "Messung stoppen", "Detener medición", "Meting stoppen", "Zatrzymaj pomiar", "停止监测"),
    "Intervall (s)": ("Interval (s)", "Intervall (s)", "Intervalo (s)", "Interval (s)", "Interwał (s)", "间隔（秒）"), "Timeout (s)": ("Timeout (s)", "Timeout (s)", "Tiempo de espera (s)", "Time-out (s)", "Limit czasu (s)", "超时（秒）"), "Parallelprozesse": ("Parallel processes", "Parallelprozesse", "Procesos paralelos", "Parallelle processen", "Procesy równoległe", "并行进程"),
    "Pings per SSH ausführen": ("Run pings over SSH", "Pings per SSH ausführen", "Ejecutar pings por SSH", "Pings via SSH uitvoeren", "Wykonuj ping przez SSH", "通过 SSH 执行 Ping"), "Firewall / SSH-Host": ("Firewall / SSH host", "Firewall / SSH-Host", "Firewall / host SSH", "Firewall / SSH-host", "Firewall / host SSH", "防火墙 / SSH 主机"), "Benutzer": ("Username", "Benutzer", "Usuario", "Gebruikersnaam", "Użytkownik", "用户名"), "Passwort": ("Password", "Passwort", "Contraseña", "Wachtwoord", "Hasło", "密码"),
    "SSH testen": ("Test SSH", "SSH testen", "Probar SSH", "SSH testen", "Testuj SSH", "测试 SSH"), "ARP / ip neigh überwachen": ("Monitor ARP / ip neigh", "ARP / ip neigh überwachen", "Supervisar ARP / ip neigh", "ARP / ip neigh bewaken", "Monitoruj ARP / ip neigh", "监控 ARP / ip neigh"), "DHCP tcpdump": ("DHCP tcpdump", "DHCP tcpdump", "DHCP tcpdump", "DHCP tcpdump", "DHCP tcpdump", "DHCP tcpdump"),
    "Ziel-Filter:": ("Target filter:", "Ziel-Filter:", "Filtro de destinos:", "Doelfilter:", "Filtr celów:", "目标筛选："), "Dauerhaft offline ausblenden": ("Hide always-offline", "Dauerhaft offline ausblenden", "Ocultar siempre desconectados", "Altijd offline verbergen", "Ukryj stale offline", "隐藏持续离线"), "Aktuell offline ausblenden": ("Hide currently offline", "Aktuell offline ausblenden", "Ocultar desconectados", "Huidig offline verbergen", "Ukryj obecnie offline", "隐藏当前离线"), "Alle": ("Select all", "Alle", "Seleccionar todo", "Alles", "Zaznacz wszystko", "全选"), "Auswahl leeren": ("Clear selection", "Auswahl leeren", "Limpiar selección", "Selectie wissen", "Wyczyść zaznaczenie", "清除选择"),
    "CSV importieren": ("Import targets", "CSV importieren", "Importar CSV", "CSV importeren", "Importuj CSV", "导入 CSV"), "Messwerte exportieren": ("Export measurements", "Messwerte exportieren", "Exportar mediciones", "Metingen exporteren", "Eksportuj pomiary", "导出测量数据"),
    "Ziele eigenes Fenster": ("Targets in separate window", "Ziele eigenes Fenster", "Destinos en ventana aparte", "Doelen in apart venster", "Cele w osobnym oknie", "在独立窗口显示目标"), "Graph eigenes Fenster": ("Graph in separate window", "Graph eigenes Fenster", "Gráfico en ventana aparte", "Grafiek in apart venster", "Wykres w osobnym oknie", "在独立窗口显示图表"), "Messwerte eigenes Fenster": ("Measurements in separate window", "Messwerte eigenes Fenster", "Mediciones en ventana aparte", "Metingen in apart venster", "Pomiary w osobnym oknie", "在独立窗口显示测量值"),
    "Ping-Ziele": ("Ping targets", "Ping-Ziele", "Destinos de ping", "Ping-doelen", "Cele ping", "Ping 目标"), "Adressen, Gerätelisten oder Netzwerktopologien einfügen.": ("Paste addresses, device lists, or network topologies.", "Adressen, Gerätelisten oder Netzwerktopologien einfügen.", "Pega direcciones, listas de dispositivos o topologías de red.", "Plak adressen, apparatenlijsten of netwerktopologieën.", "Wklej adresy, listy urządzeń lub topologie sieci.", "粘贴地址、设备列表或网络拓扑。"), "Ziele hinzufügen": ("Add targets", "Ziele hinzufügen", "Añadir destinos", "Doelen toevoegen", "Dodaj cele", "添加目标"), "Auswahl entfernen": ("Remove selected", "Auswahl entfernen", "Eliminar selección", "Selectie verwijderen", "Usuń zaznaczone", "移除所选项"), "Zielstatus": ("Target status", "Zielstatus", "Estado de destinos", "Doelstatus", "Stan celu", "目标状态"), "Namen, IP-Adressen und Markdown-Tabellen werden erkannt.": ("Names, IP addresses, and Markdown tables are detected.", "Namen, IP-Adressen und Markdown-Tabellen werden erkannt.", "Se reconocen nombres, direcciones IP y tablas Markdown.", "Namen, IP-adressen en Markdown-tabellen worden herkend.", "Nazwy, adresy IP i tabele Markdown są rozpoznawane.", "可识别名称、IP 地址和 Markdown 表格。"),
    "Hostname": ("Hostname", "Hostname", "Nombre de host", "Hostnaam", "Nazwa hosta", "主机名"), "IP-Adresse / Ziel": ("IP address / target", "IP-Adresse / Ziel", "IP / destino", "IP-adres / doel", "Adres IP / cel", "IP 地址 / 目标"), "MAC-Adresse": ("MAC address", "MAC-Adresse", "Dirección MAC", "MAC-adres", "Adres MAC", "MAC 地址"), "Status": ("Status", "Status", "Estado", "Status", "Stan", "状态"), "Letzter Ping": ("Last ping", "Letzter Ping", "Último ping", "Laatste ping", "Ostatni ping", "上次 Ping"), "Letzter Erfolg": ("Last success", "Letzter Erfolg", "Último éxito", "Laatste succes", "Ostatni sukces", "上次成功"), "Verlust": ("Loss", "Verlust", "Pérdida", "Verlies", "Utrata", "丢包"), "Letzter Verlust": ("Last loss", "Letzter Verlust", "Última pérdida", "Laatste verlies", "Ostatnia utrata", "上次丢包"),
    "Latenzverlauf": ("Latency history", "Latenzverlauf", "Historial de latencia", "Latentiegeschiedenis", "Historia opóźnień", "延迟历史"), "Eigenes Fenster": ("Separate window", "Eigenes Fenster", "Ventana aparte", "Apart venster", "Osobne okno", "独立窗口"), "Zeitraum": ("Time range", "Zeitraum", "Periodo", "Tijdsbereik", "Zakres czasu", "时间范围"), "Gesamter Verlauf": ("All history", "Gesamter Verlauf", "Todo el historial", "Volledige geschiedenis", "Cała historia", "全部历史"), "Letzte 30 Sekunden": ("Last 30 seconds", "Letzte 30 Sekunden", "Últimos 30 segundos", "Laatste 30 seconden", "Ostatnie 30 sekund", "最近 30 秒"), "Letzte 5 Minuten": ("Last 5 minutes", "Letzte 5 Minuten", "Últimos 5 minutos", "Laatste 5 minuten", "Ostatnie 5 minut", "最近 5 分钟"), "Letzte 15 Minuten": ("Last 15 minutes", "Letzte 15 Minuten", "Últimos 15 minutos", "Laatste 15 minuten", "Ostatnie 15 minut", "最近 15 分钟"), "Letzte Stunde": ("Last hour", "Letzte Stunde", "Última hora", "Afgelopen uur", "Ostatnia godzina", "最近 1 小时"), "Letzte 6 Stunden": ("Last 6 hours", "Letzte 6 Stunden", "Últimas 6 horas", "Laatste 6 uur", "Ostatnie 6 godzin", "最近 6 小时"), "Eigene relative Dauer": ("Custom relative duration", "Eigene relative Dauer", "Duración relativa personalizada", "Aangepaste relatieve duur", "Własny czas względny", "自定义相对时长"), "Benutzerdefiniert": ("Custom", "Benutzerdefiniert", "Personalizado", "Aangepast", "Niestandardowy", "自定义"), "Von (YYYY-MM-DD HH:MM:SS)": ("From (YYYY-MM-DD HH:MM:SS)", "Von (YYYY-MM-DD HH:MM:SS)", "Desde (YYYY-MM-DD HH:MM:SS)", "Van (YYYY-MM-DD HH:MM:SS)", "Od (YYYY-MM-DD HH:MM:SS)", "从（YYYY-MM-DD HH:MM:SS）"), "Bis": ("To", "Bis", "Hasta", "Tot", "Do", "至"), "Anwenden": ("Apply", "Anwenden", "Aplicar", "Toepassen", "Zastosuj", "应用"), "Eigene relative Dauer: letzte": ("Custom relative duration: last", "Eigene relative Dauer: letzte", "Duración relativa personalizada: últimos", "Aangepaste relatieve duur: laatste", "Własny czas względny: ostatnie", "自定义相对时长：最近"), "Sekunden": ("Seconds", "Sekunden", "Segundos", "Seconden", "Sekundy", "秒"), "Minuten": ("Minutes", "Minuten", "Minutos", "Minuten", "Minuty", "分钟"), "Stunden": ("Hours", "Stunden", "Horas", "Uren", "Godziny", "小时"), "Messwertverlauf · im Arbeitsspeicher": ("Measurements · in memory", "Messwertverlauf · im Arbeitsspeicher", "Mediciones · en memoria", "Metingen · in geheugen", "Pomiary · w pamięci", "测量数据 · 内存中"),
    "Schnittstellen laden": ("Load interfaces", "Schnittstellen laden", "Cargar interfaces", "Interfaces laden", "Wczytaj interfejsy", "加载接口"), "Aufzeichnung starten": ("Start capture", "Aufzeichnung starten", "Iniciar captura", "Opname starten", "Rozpocznij przechwytywanie", "开始捕获"), "Aufzeichnung stoppen": ("Stop capture", "Aufzeichnung stoppen", "Detener captura", "Opname stoppen", "Zatrzymaj przechwytywanie", "停止捕获"), "Pakete als CSV exportieren": ("Export packets as CSV", "Pakete als CSV exportieren", "Exportar paquetes como CSV", "Pakketten exporteren als CSV", "Eksportuj pakiety jako CSV", "导出数据包为 CSV"), "Interfaces · Live-Filter": ("Interfaces · live filter", "Interfaces · Live-Filter", "Interfaces · filtro en vivo", "Interfaces · livefilter", "Interfejsy · filtr na żywo", "接口 · 实时筛选"), "Wähle ein oder mehrere Interfaces. Die Aufzeichnung läuft parallel auf any.": ("Select one or more interfaces. Capture continues on any.", "Wähle ein oder mehrere Interfaces. Die Aufzeichnung läuft parallel auf any.", "Selecciona una o varias interfaces. La captura continúa en any.", "Selecteer een of meer interfaces. De opname loopt via any.", "Wybierz jeden lub więcej interfejsów. Przechwytywanie działa na any.", "选择一个或多个接口。捕获将在 any 上持续运行。"), "DHCP-Pakete": ("DHCP packets", "DHCP-Pakete", "Paquetes DHCP", "DHCP-pakketten", "Pakiety DHCP", "DHCP 数据包"), "Paketdetails · DHCP-Optionen und tcpdump-Decodierung": ("Packet details · DHCP options and tcpdump decode", "Paketdetails · DHCP-Optionen und tcpdump-Decodierung", "Detalles · opciones DHCP y decodificación tcpdump", "Pakketdetails · DHCP-opties en tcpdump-decodering", "Szczegóły pakietu · opcje DHCP i dekodowanie tcpdump", "数据包详情 · DHCP 选项和 tcpdump 解码"),
    "Zeitstempel": ("Timestamp", "Zeitstempel", "Marca de tiempo", "Tijdstempel", "Znacznik czasu", "时间戳"), "Interface": ("Interface", "Interface", "Interfaz", "Interface", "Interfejs", "接口"), "Richtung": ("Direction", "Richtung", "Dirección", "Richting", "Kierunek", "方向"), "DHCP-Nachricht": ("DHCP message", "DHCP-Nachricht", "Mensaje DHCP", "DHCP-bericht", "Komunikat DHCP", "DHCP 消息"), "Quelle": ("Source", "Quelle", "Origen", "Bron", "Źródło", "来源"), "Ziel": ("Destination", "Ziel", "Destino", "Bestemming", "Cel", "目标"), "Client-MAC": ("Client MAC", "Client-MAC", "MAC del cliente", "Client-MAC", "MAC klienta", "客户端 MAC"), "Transaktions-ID": ("Transaction ID", "Transaktions-ID", "ID de transacción", "Transactie-ID", "ID transakcji", "事务 ID"),
    "Zeitpunkt": ("Time", "Zeitpunkt", "Fecha y hora", "Tijdstip", "Czas", "时间"), "IP-Adresse": ("IP address", "IP-Adresse", "Dirección IP", "IP-adres", "Adres IP", "IP 地址"), "Nachbarstatus": ("Neighbor state", "Nachbarstatus", "Estado del vecino", "Neighbor-status", "Stan sąsiada", "邻居状态"), "Aktuell": ("Current", "Aktuell", "Actual", "Huidig", "Bieżący", "当前"), "Erstmals gesehen": ("First seen", "Erstmals gesehen", "Visto por primera vez", "Eerst gezien", "Widziano po raz pierwszy", "首次发现"), "Zuletzt gesehen": ("Last seen", "Zuletzt gesehen", "Visto por última vez", "Laatst gezien", "Ostatnio widziano", "上次发现"), "Änderungen · dauerhaft markiert": ("Changes · persistently marked", "Änderungen · dauerhaft markiert", "Cambios · marcados permanentemente", "Wijzigingen · blijvend gemarkeerd", "Zmiany · trwale oznaczone", "变更 · 持续标记"), "Sichtbarkeit": ("Presence", "Sichtbarkeit", "Presencia", "Aanwezigheid", "Obecność", "可见状态"), "Änderung bei diesem Snapshot": ("Change in this snapshot", "Änderung bei diesem Snapshot", "Cambio en esta captura", "Wijziging in deze momentopname", "Zmiana w tym odczycie", "本次快照中的变更"), "Änderung": ("Change", "Änderung", "Cambio", "Wijziging", "Zmiana", "变更"), "Details": ("Details", "Details", "Detalles", "Details", "Szczegóły", "详情"),
    "Ping-Ziele und Status": ("Ping targets and status", "Ping-Ziele und Status", "Destinos ping y estado", "Ping-doelen en status", "Cele ping i stan", "Ping 目标和状态"), "Ziele aus diesem Text hinzufügen": ("Add targets from this text", "Ziele aus diesem Text hinzufügen", "Añadir destinos desde este texto", "Doelen uit deze tekst toevoegen", "Dodaj cele z tego tekstu", "从此文本添加目标"), "Messwertverlauf · Live": ("Measurement history · live", "Messwertverlauf · Live", "Historial de mediciones · en vivo", "Meetgeschiedenis · live", "Historia pomiarów · na żywo", "测量历史 · 实时"), "pingee · Latenzverlauf": ("pingee · Latency history", "pingee · Latenzverlauf", "pingee · Historial de latencia", "pingee · Latentiegeschiedenis", "pingee · Historia opóźnień", "pingee · 延迟历史"),
    "Hostname:": ("Hostname:", "Hostname:", "Nombre de host:", "Hostnaam:", "Nazwa hosta:", "主机名："), "Zeit:": ("Time:", "Zeit:", "Hora:", "Tijd:", "Czas:", "时间："), "Latenz:": ("Latency:", "Latenz:", "Latencia:", "Latentie:", "Opóźnienie:", "延迟："), "Ergebnis:": ("Result:", "Ergebnis:", "Resultado:", "Resultaat:", "Wynik:", "结果："), "Paketverlust / Timeout": ("Packet loss / timeout", "Paketverlust / Timeout", "Pérdida de paquetes / tiempo agotado", "Pakketverlies / time-out", "Utrata pakietu / limit czasu", "丢包 / 超时"),
    "Bewege den Mauszeiger über einen Messpunkt für Details.": ("Hover over a measurement point for details.", "Bewege den Mauszeiger über einen Messpunkt für Details.", "Pasa el cursor sobre un punto para ver los detalles.", "Beweeg de muis over een meetpunt voor details.", "Najedź kursorem na punkt pomiaru, aby zobaczyć szczegóły.", "将鼠标悬停在测量点上以查看详情。"), "MAC:": ("MAC:", "MAC:", "MAC:", "MAC:", "MAC:", "MAC："), "Prüfe …": ("Testing …", "Prüfe …", "Probando …", "Testen …", "Testowanie …", "正在测试…"),
    "Direction:": ("Direction:", "Richtung:", "Dirección:", "Richting:", "Kierunek:", "方向："), "Message:": ("Message:", "Nachricht:", "Mensaje:", "Bericht:", "Komunikat:", "消息："), "Source:": ("Source:", "Quelle:", "Origen:", "Bron:", "Źródło:", "来源："), "Destination:": ("Destination:", "Ziel:", "Destino:", "Bestemming:", "Cel:", "目标："), "Packet decoding:": ("Packet decoding:", "Rohpaket-Decodierung:", "Decodificación del paquete:", "Pakketdecodering:", "Dekodowanie pakietu:", "数据包解码："),
    "Uhrzeit": ("Time", "Uhrzeit", "Hora", "Tijd", "Czas", "时间"), "Messung starten, um Latenzwerte zu sehen": ("Start monitoring to view latency", "Messung starten, um Latenzwerte zu sehen", "Inicia la medición para ver la latencia", "Start de meting om latentie te bekijken", "Uruchom pomiar, aby zobaczyć opóźnienia", "开始监测以查看延迟"), "Relative Dauer ungültig": ("Invalid relative duration", "Relative Dauer ungültig", "Duración relativa no válida", "Ongeldige relatieve duur", "Nieprawidłowy czas względny", "相对时长无效"), "Zeitfenster ungültig": ("Invalid time range", "Zeitfenster ungültig", "Intervalo no válido", "Ongeldig tijdsbereik", "Nieprawidłowy zakres czasu", "时间范围无效"), "Keine Messwerte": ("No measurements", "Keine Messwerte", "Sin mediciones", "Geen metingen", "Brak pomiarów", "没有测量数据"), "Es gibt noch keine Messwerte zum Speichern.": ("There are no measurements to save yet.", "Es gibt noch keine Messwerte zum Speichern.", "Aún no hay mediciones para guardar.", "Er zijn nog geen meetgegevens om op te slaan.", "Nie ma jeszcze pomiarów do zapisania.", "暂无可保存的测量数据。"), "Export fehlgeschlagen": ("Export failed", "Export fehlgeschlagen", "Error al exportar", "Export mislukt", "Eksport nie powiódł się", "导出失败"), "Speichern fehlgeschlagen": ("Save failed", "Speichern fehlgeschlagen", "Error al guardar", "Opslaan mislukt", "Zapis nie powiódł się", "保存失败"),
    "Messung gestoppt · Messwerte bleiben im Arbeitsspeicher erhalten": ("Monitoring stopped · measurements remain in memory", "Messung gestoppt · Messwerte bleiben im Arbeitsspeicher erhalten", "Medición detenida · los datos permanecen en memoria", "Meting gestopt · meetgegevens blijven in het geheugen", "Pomiar zatrzymany · dane pozostają w pamięci", "监测已停止 · 测量数据保留在内存中"), "Überwachung gestoppt · gespeicherte Beobachtungen bleiben erhalten": ("Monitoring stopped · saved observations are retained", "Überwachung gestoppt · gespeicherte Beobachtungen bleiben erhalten", "Supervisión detenida · se conservan las observaciones", "Bewaking gestopt · opgeslagen waarnemingen blijven behouden", "Monitorowanie zatrzymane · zapisane obserwacje są zachowane", "监控已停止 · 已保存的观察记录仍保留"), "Änderungsmarkierungen zurückgesetzt · Beobachtungs- und Ereignisverlauf bleibt erhalten": ("Change marks reset · observation and event history retained", "Änderungsmarkierungen zurückgesetzt · Beobachtungs- und Ereignisverlauf bleibt erhalten", "Marcas restablecidas · se conserva el historial", "Wijzigingsmarkeringen gewist · geschiedenis blijft behouden", "Oznaczenia zmian zresetowane · historia zachowana", "变更标记已重置 · 观察和事件历史仍保留"),
    "Keine Ziele erkannt": ("No targets found", "Keine Ziele erkannt", "No se encontraron destinos", "Geen doelen gevonden", "Nie znaleziono celów", "未识别到目标"), "Bitte gültige IP-Adressen oder Hostnamen einfügen.": ("Please paste valid IP addresses or hostnames.", "Bitte gültige IP-Adressen oder Hostnamen einfügen.", "Pega direcciones IP o nombres de host válidos.", "Plak geldige IP-adressen of hostnamen.", "Wklej prawidłowe adresy IP lub nazwy hostów.", "请粘贴有效的 IP 地址或主机名。"), "CSV-Import fehlgeschlagen": ("CSV import failed", "CSV-Import fehlgeschlagen", "Error al importar CSV", "CSV-import mislukt", "Import CSV nie powiódł się", "CSV 导入失败"), "Ungültige Einstellung": ("Invalid setting", "Ungültige Einstellung", "Configuración no válida", "Ongeldige instelling", "Nieprawidłowe ustawienie", "设置无效"), "Intervall und Timeout müssen Zahlen sein.": ("Interval and timeout must be numbers.", "Intervall und Timeout müssen Zahlen sein.", "El intervalo y el tiempo de espera deben ser números.", "Interval en time-out moeten getallen zijn.", "Interwał i limit czasu muszą być liczbami.", "间隔和超时必须为数字。"), "SSH-Daten fehlen": ("SSH credentials missing", "SSH-Daten fehlen", "Faltan datos de SSH", "SSH-gegevens ontbreken", "Brak danych SSH", "缺少 SSH 凭据"), "Bitte Host, Benutzer und Passwort eingeben.": ("Enter host, username, and password.", "Bitte Host, Benutzer und Passwort eingeben.", "Introduce el host, el usuario y la contraseña.", "Voer host, gebruikersnaam en wachtwoord in.", "Wpisz host, użytkownika i hasło.", "请输入主机、用户名和密码。"), "Bitte zuerst Host, Benutzer und Passwort im SSH-Bereich eingeben.": ("Enter the host, username, and password in the SSH section first.", "Bitte zuerst Host, Benutzer und Passwort im SSH-Bereich eingeben.", "Introduce primero el host, usuario y contraseña en la sección SSH.", "Voer eerst de host, gebruikersnaam en het wachtwoord in bij SSH.", "Najpierw wpisz host, użytkownika i hasło w sekcji SSH.", "请先在 SSH 区域输入主机、用户名和密码。"), "SSH-Test fehlgeschlagen": ("SSH test failed", "SSH-Test fehlgeschlagen", "Error en prueba SSH", "SSH-test mislukt", "Test SSH nie powiódł się", "SSH 测试失败"),
    "Keine DHCP-Pakete": ("No DHCP packets", "Keine DHCP-Pakete", "No hay paquetes DHCP", "Geen DHCP-pakketten", "Brak pakietów DHCP", "没有 DHCP 数据包"), "Es wurden noch keine DHCP-Pakete empfangen.": ("No DHCP packets have been received yet.", "Es wurden noch keine DHCP-Pakete empfangen.", "Aún no se han recibido paquetes DHCP.", "Er zijn nog geen DHCP-pakketten ontvangen.", "Nie odebrano jeszcze pakietów DHCP.", "尚未收到 DHCP 数据包。"), "Keine Beobachtungen": ("No observations", "Keine Beobachtungen", "Sin observaciones", "Geen waarnemingen", "Brak obserwacji", "没有观察记录"), "Es wurden noch keine ARP-/ip-neigh-Beobachtungen gespeichert.": ("No ARP / ip neigh observations have been saved yet.", "Es wurden noch keine ARP-/ip-neigh-Beobachtungen gespeichert.", "Aún no se han guardado observaciones ARP / ip neigh.", "Er zijn nog geen ARP-/ip-neigh-waarnemingen opgeslagen.", "Nie zapisano jeszcze obserwacji ARP / ip neigh.", "尚未保存 ARP / ip neigh 观察记录。"), "Ungültiges Intervall": ("Invalid interval", "Ungültiges Intervall", "Intervalo no válido", "Ongeldig interval", "Nieprawidłowy interwał", "间隔无效"), "Das Abfrageintervall muss eine Zahl von mindestens 2 Sekunden sein.": ("The polling interval must be at least 2 seconds.", "Das Abfrageintervall muss eine Zahl von mindestens 2 Sekunden sein.", "El intervalo de consulta debe ser de al menos 2 segundos.", "Het pollinterval moet minimaal 2 seconden zijn.", "Interwał odpytywania musi wynosić co najmniej 2 sekundy.", "轮询间隔必须至少为 2 秒。"), "Verlauf zurücksetzen": ("Reset history", "Verlauf zurücksetzen", "Restablecer historial", "Geschiedenis resetten", "Zresetuj historię", "重置历史"),
    "Netzwerkgeräte · unabhängig von Ping-Zielen": ("Network devices · independent of ping targets", "Netzwerkgeräte · unabhängig von Ping-Zielen", "Dispositivos de red · independientes de los pings", "Netwerkapparaten · onafhankelijk van ping-doelen", "Urządzenia sieciowe · niezależne od celów ping", "网络设备 · 独立于 Ping 目标"), "Abfrageintervall (s)": ("Polling interval (s)", "Abfrageintervall (s)", "Intervalo de consulta (s)", "Pollinterval (s)", "Interwał odpytywania (s)", "轮询间隔（秒）"), "Überwachung starten": ("Start monitoring", "Überwachung starten", "Iniciar supervisión", "Bewaking starten", "Rozpocznij monitorowanie", "开始监控"), "Stopp": ("Stop", "Stopp", "Detener", "Stop", "Stop", "停止"), "Änderungsmarkierungen zurücksetzen": ("Reset change marks", "Änderungsmarkierungen zurücksetzen", "Restablecer marcas", "Wijzigingsmarkeringen resetten", "Zresetuj oznaczenia zmian", "重置变更标记"), "Verlauf exportieren": ("Export history", "Verlauf exportieren", "Exportar historial", "Geschiedenis exporteren", "Eksportuj historię", "导出历史"), "Geräte aktuell": ("Current devices", "Geräte aktuell", "Dispositivos actuales", "Huidige apparaten", "Bieżące urządzenia", "当前设备"), "Beobachtungsverlauf": ("Observation history", "Beobachtungsverlauf", "Historial de observaciones", "Observatiegeschiedenis", "Historia obserwacji", "观察历史"), "Änderungsereignisse": ("Change events", "Änderungsereignisse", "Eventos de cambio", "Wijzigingsgebeurtenissen", "Zdarzenia zmian", "变更事件"), "Änderungen anzeigen:": ("Show changes:", "Änderungen anzeigen:", "Mostrar cambios:", "Wijzigingen tonen:", "Pokaż zmiany:", "显示变更："), "Neue / wiederkehrende Geräte": ("New / returning devices", "Neue / wiederkehrende Geräte", "Dispositivos nuevos / recurrentes", "Nieuwe / terugkerende apparaten", "Nowe / powracające urządzenia", "新出现 / 重新出现的设备"), "Verschwundene Geräte": ("Disappeared devices", "Verschwundene Geräte", "Dispositivos desaparecidos", "Verdwenen apparaten", "Zaginione urządzenia", "消失的设备"), "MAC / Interface": ("MAC / interface", "MAC / Interface", "MAC / interfaz", "MAC / interface", "MAC / interfejs", "MAC / 接口"), "Neighbor-Statuswechsel": ("Neighbor state changes", "Neighbor-Statuswechsel", "Cambios de estado de vecino", "Neighbor-statuswijzigingen", "Zmiany stanu sąsiada", "邻居状态变化"),
    "Bereit": ("Ready", "Bereit", "Listo", "Gereed", "Gotowe", "就绪"), "OK": ("OK", "OK", "Correcto", "OK", "OK", "正常"), "Zeitüberschreitung": ("Timed out", "Zeitüberschreitung", "Tiempo agotado", "Time-out", "Limit czasu", "超时"),
    "SSH-Verbindung erfolgreich": ("SSH connection successful", "SSH-Verbindung erfolgreich", "Conexión SSH correcta", "SSH-verbinding geslaagd", "Połączenie SSH udane", "SSH 连接成功"), "SSH-Verbindung fehlgeschlagen": ("SSH connection failed", "SSH-Verbindung fehlgeschlagen", "Error en conexión SSH", "SSH-verbinding mislukt", "Połączenie SSH nieudane", "SSH 连接失败"),
}

STATUS_TRANSLATIONS = {
    "targets_added": ("{count} target(s) added · {total} total", "{count} Ziel(e) hinzugefügt · {total} insgesamt", "{count} destino(s) añadido(s) · {total} en total", "{count} doel(en) toegevoegd · {total} totaal", "Dodano {count} celów · łącznie {total}", "已添加 {count} 个目标 · 共 {total} 个"),
    "csv_imported": ("CSV imported · {count} new target(s)", "CSV importiert · {count} neue Ziele", "CSV importado · {count} destino(s) nuevo(s)", "CSV geïmporteerd · {count} nieuwe doelen", "Zaimportowano CSV · nowe cele: {count}", "CSV 已导入 · 新增目标 {count} 个"),
    "measurement_active": ("Monitoring active · {count} target(s) · {capacity} · interval {interval} s", "Messung aktiv · {count} Ziel(e) · {capacity} · Intervall {interval} s", "Medición activa · {count} destino(s) · {capacity} · intervalo {interval} s", "Meting actief · {count} doel(en) · {capacity} · interval {interval} s", "Pomiar aktywny · cele: {count} · {capacity} · interwał {interval} s", "监测运行中 · {count} 个目标 · {capacity} · 间隔 {interval} 秒"),
    "measurement_stopped": ("Monitoring stopped · measurements remain in memory", "Messung gestoppt · Messwerte bleiben im Arbeitsspeicher erhalten", "Medición detenida · los datos permanecen en memoria", "Meting gestopt · meetgegevens blijven in het geheugen", "Pomiar zatrzymany · dane pozostają w pamięci", "监测已停止 · 测量数据保留在内存中"),
    "dhcp_loading": ("Loading interfaces on {host} …", "Netzwerkschnittstellen auf {host} werden gelesen …", "Leyendo interfaces de {host} …", "Interfaces op {host} laden …", "Wczytywanie interfejsów z {host} …", "正在读取 {host} 上的网络接口…"),
    "dhcp_interfaces_loaded": ("{count} interface(s) loaded · any captures all; selection filters the display", "{count} Interface(s) geladen · any zeichnet alle Interfaces auf; die Auswahl filtert die Anzeige.", "{count} interfaz(es) cargada(s) · any captura todo; la selección filtra la vista", "{count} interface(s) geladen · any neemt alles op; selectie filtert de weergave", "Wczytano interfejsy: {count} · any przechwytuje wszystko; wybór filtruje widok", "已加载 {count} 个接口 · any 捕获全部；选择项筛选显示内容"),
    "dhcp_starting": ("Starting tcpdump on any …", "tcpdump wird auf any gestartet …", "Iniciando tcpdump en any …", "tcpdump starten op any …", "Uruchamianie tcpdump na any …", "正在 any 上启动 tcpdump…"),
    "dhcp_stopped": ("Capture stopped · {count} packet(s) in memory", "Aufzeichnung gestoppt · {count} Paket(e) im Arbeitsspeicher", "Captura detenida · {count} paquete(s) en memoria", "Opname gestopt · {count} pakket(ten) in geheugen", "Przechwytywanie zatrzymane · pakiety w pamięci: {count}", "捕获已停止 · 内存中有 {count} 个数据包"),
    "neighbor_stopped": ("Monitoring stopped · observations remain available", "Überwachung gestoppt · gespeicherte Beobachtungen bleiben erhalten", "Supervisión detenida · las observaciones se conservan", "Bewaking gestopt · waarnemingen blijven bewaard", "Monitorowanie zatrzymane · obserwacje pozostają zapisane", "监控已停止 · 已保存的观察记录仍保留"),
    "ssh_capacity": ("Persistent SSH shells · up to {pings} remote pings / {channels} channels", "SSH-Dauershells · max. {pings} Remote-Pings / {channels} Kanäle", "Shells SSH persistentes · hasta {pings} pings remotos / {channels} canales", "Permanente SSH-shells · max. {pings} remote pings / {channels} kanalen", "Trwałe powłoki SSH · do {pings} pingów zdalnych / kanałów: {channels}", "持久 SSH Shell · 最多 {pings} 个远程 Ping / {channels} 个通道"),
    "local_capacity": ("Local · up to {count} ping processes", "Lokal · max. {count} Prozesse", "Local · hasta {count} procesos ping", "Lokaal · maximaal {count} ping-processen", "Lokalnie · maks. procesów ping: {count}", "本地 · 最多 {count} 个 Ping 进程"),
    "first_round_progress": ("First pass {done}/{total} · ", "Erste Runde {done}/{total} · ", "Primera ronda {done}/{total} · ", "Eerste ronde {done}/{total} · ", "Pierwszy przebieg {done}/{total} · ", "首次扫描 {done}/{total} · "),
    "first_round_duration": ("First pass {seconds:.1f} s · ", "Erste Runde {seconds:.1f} s · ", "Primera ronda {seconds:.1f} s · ", "Eerste ronde {seconds:.1f} s · ", "Pierwszy przebieg {seconds:.1f} s · ", "首次扫描 {seconds:.1f} 秒 · "),
    "health_summary": ("Online {online} · Offline {offline} · unchecked {unchecked} · MAC {macs}/{total} · {source}", "Online {online} · Offline {offline} · ungeprüft {unchecked} · MAC {macs}/{total} · {source}", "En línea {online} · Fuera de línea {offline} · sin comprobar {unchecked} · MAC {macs}/{total} · {source}", "Online {online} · Offline {offline} · niet getest {unchecked} · MAC {macs}/{total} · {source}", "Online {online} · Offline {offline} · niesprawdzone {unchecked} · MAC {macs}/{total} · {source}", "在线 {online} · 离线 {offline} · 未检查 {unchecked} · MAC {macs}/{total} · {source}"),
    "neighbor_already_running": ("Monitoring is already running", "Überwachung läuft bereits", "La supervisión ya está en marcha", "Bewaking is al actief", "Monitorowanie już działa", "监控已在运行"),
    "dhcp_no_interfaces": ("Load interfaces first", "Bitte zuerst Netzwerkschnittstellen laden.", "Carga primero las interfaces", "Laad eerst de interfaces", "Najpierw wczytaj interfejsy", "请先加载网络接口"),
    "dhcp_running": ("tcpdump running on any · receiving DHCPv4/v6 packets", "tcpdump läuft auf any · DHCPv4/v6-Pakete werden empfangen", "tcpdump activo en any · recibiendo paquetes DHCPv4/v6", "tcpdump actief op any · DHCPv4/v6-pakketten worden ontvangen", "tcpdump działa na any · odbieranie pakietów DHCPv4/v6", "tcpdump 正在 any 上运行 · 接收 DHCPv4/v6 数据包"),
    "ssh_success": ("SSH successful · {host} · hostname: {hostname}", "SSH erfolgreich · {host} · Hostname: {hostname}", "SSH correcto · {host} · nombre de host: {hostname}", "SSH geslaagd · {host} · hostnaam: {hostname}", "SSH działa · {host} · nazwa hosta: {hostname}", "SSH 成功 · {host} · 主机名：{hostname}"),
    "ssh_failed": ("SSH failed · {host} · {error}", "SSH fehlgeschlagen · {host} · {error}", "Error SSH · {host} · {error}", "SSH mislukt · {host} · {error}", "SSH nieudane · {host} · {error}", "SSH 失败 · {host} · {error}"),
    "neighbor_snapshot": ("Snapshot {count} · {time} · {devices} devices · {marked} persistently marked · {observations} observations in memory", "Snapshot {count} · {time} · {devices} Geräte aktuell · {marked} dauerhaft markiert · {observations} Beobachtungen im Arbeitsspeicher", "Instantánea {count} · {time} · {devices} dispositivos · {marked} marcados permanentemente · {observations} observaciones en memoria", "Momentopname {count} · {time} · {devices} apparaten · {marked} blijvend gemarkeerd · {observations} waarnemingen in geheugen", "Migawka {count} · {time} · urządzenia: {devices} · trwale oznaczone: {marked} · obserwacje w pamięci: {observations}", "快照 {count} · {time} · 设备 {devices} 台 · 持续标记 {marked} 项 · 内存观察记录 {observations} 条"),
}


def parse_targets(text: str) -> list[tuple[str, str, str]]:
    """Parse pasted text or inventory tables into normalized target records.

Recognizes IP addresses and hostnames in plain lists, Markdown tables, tab-separated device exports, and supported network-topology layouts. Duplicate addresses are collapsed while the best available hostname is retained. Each result is a three-item tuple: ``(address, hostname, mac_address)``; the MAC value is empty when the input contains none."""
    found: list[tuple[str, str]] = []
    seen: dict[str, int] = {}
    row_macs: dict[str, str] = {}

    def add(value: str, label: str = "") -> None:
        """Normalize one candidate address, hostname, or label and deduplicate it.

If a duplicate address is found, preserve an existing hostname or upgrade an unlabeled entry when the new row provides a useful label."""
        value = value.strip().strip("[](){}<>;,'\"`")
        if not value:
            return
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not HOST_RE.fullmatch(value):
                return
        key = value.casefold()
        if key in seen:
            old_value, old_label = found[seen[key]]
            if not old_label and label:
                found[seen[key]] = (old_value, label.strip())
        else:
            seen[key] = len(found)
            found.append((value, label.strip()))

    def is_host(value: str) -> bool:
        """Return whether a token is a valid hostname label for inventory parsing.

The parser accepts ordinary DNS names and single-label device names while rejecting protocol names, table headings, and malformed punctuation."""
        if not value or IP_RE.fullmatch(value):
            return False
        return bool(HOST_RE.fullmatch(value) or HOST_LABEL_RE.fullmatch(value))

    last_target = ""
    # CSV-like lines: use a likely IP/host field and its adjacent descriptive name.
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("| :-", "| :--", "---")):
            continue
        delimiter = "\t" if "\t" in line else (";" if ";" in line and "|" not in line else "|")
        cells = [c.strip().strip("*").strip() for c in line.strip("|").split(delimiter)]
        # Device-list exports often have columns like On, Name, Address, Domain, Vendor, MAC.
        # Preserve the friendly name, but use the address column as the ping target.
        ipv4_cells = []
        for i, cell in enumerate(cells):
            match = IP_RE.fullmatch(cell)
            if match:
                try:
                    ipaddress.ip_address(cell)
                    ipv4_cells.append((i, cell))
                except ValueError:
                    pass
        if ipv4_cells:
            hostname = ""
            if len(cells) > 1 and cells[0].casefold() == "on":
                for cell in cells[1:ipv4_cells[0][0]]:
                    if is_host(cell):
                        hostname = cell
                        break
            else:
                # Firewall table format: pool section heading, then Type, Host, IP, ...
                for ip_index, _address in ipv4_cells:
                    prior = cells[:ip_index]
                    if len(prior) >= 2 and prior[-2].casefold() in {"dynamisch", "statisch", "dynamic", "static"}:
                        candidate = prior[-1]
                        if is_host(candidate):
                            hostname = candidate
                    break
            for ip_position, (ip_index, address) in enumerate(ipv4_cells):
                add(address, hostname if ip_position == 0 else "")
                last_target = address
                for cell in cells[ip_index + 1:]:
                    mac = MAC_RE.search(cell)
                    if mac:
                        row_macs[address] = mac.group(0).lower()
                        break
            continue
        # Some plain-text exports wrap the MAC/date fields onto the next line.
        wrapped_mac = MAC_RE.search(line)
        if wrapped_mac and last_target:
            row_macs[last_target] = wrapped_mac.group(0).lower()
        candidates: list[tuple[str, str]] = []
        for cell in cells:
            for match in IP_RE.findall(cell):
                candidates.append((match, ""))
            for match in HOST_RE.findall(cell):
                if "@" not in cell:
                    candidates.append((match, ""))
        for value, _ in candidates:
            label = ""
            # In firewall/network exports, a device label commonly precedes the IP cell.
            for i, cell in enumerate(cells):
                if value in cell:
                    for prior in reversed(cells[max(0, i - 3):i]):
                        if prior and prior not in ("*", "Pool", "Typ", "Host", "IP-Adresse", "MAC") and not IP_RE.search(prior):
                            label = prior
                            break
                    break
            add(value, label)
    # Also accept standalone hosts/addresses and URL/mailto content anywhere in pasted text.
    for match in IP_RE.findall(text):
        add(match)
    for match in HOST_RE.findall(text):
        add(match)
    return [(address, hostname, row_macs.get(address, "")) for address, hostname in found]


def parse_neighbor_table(text: str) -> dict[str, dict[str, str]]:
    """Parse Linux ``ip neigh`` output or classic ``arp -an`` output.

Return a mapping keyed by normalized IP address. Each value contains ``mac``, ``interface``, ``state``, and the original ``raw`` line; missing fields are represented by empty strings."""
    neighbors: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        address = ""
        for token in line.split():
            candidate = token.strip("()[],:;").split("%", 1)[0]
            try:
                address = str(ipaddress.ip_address(candidate))
                break
            except ValueError:
                continue
        if not address:
            continue
        mac = MAC_RE.search(line)
        interface = re.search(r"\b(?:dev|on)\s+(\S+)", line, re.I)
        state = next((token.upper() for token in reversed(line.split()) if token.upper() in NEIGHBOR_STATES), "")
        neighbors[address] = {
            "mac": mac.group(0).lower() if mac else "",
            "interface": interface.group(1).strip(" ,;") if interface else "",
            "state": state,
            "raw": line.strip(),
        }
    return neighbors


def parse_network_interfaces(text: str) -> dict[str, list[str]]:
    """Parse ``ip -o link show`` plus ``ip -o addr show`` into interface/IP pairs."""
    interfaces: dict[str, list[str]] = {}
    in_addresses = False
    for line in text.splitlines():
        if line.strip() == "__PPLOT_IP_ADDR__":
            in_addresses = True
            continue
        if not in_addresses:
            link = re.match(r"^\d+:\s+([^:@]+)(?:@[^:]+)?:", line)
            if link:
                interfaces.setdefault(link.group(1), [])
            continue
        address = re.match(r"^\d+:\s+([^ ]+)\s+inet6?\s+([^ ]+)", line)
        if address:
            name = address.group(1).split("@", 1)[0]
            raw_address = address.group(2).split("%", 1)[0]
            try:
                parsed = str(ipaddress.ip_interface(raw_address).ip)
            except ValueError:
                parsed = raw_address
            interfaces.setdefault(name, [])
            if parsed not in interfaces[name]:
                interfaces[name].append(parsed)
    return interfaces


def parse_dhcp_packet(lines: list[str]) -> dict[str, str] | None:
    """Extract common DHCPv4/v6 fields while retaining the full tcpdump decode."""
    raw = "\n".join(lines).strip()
    if not raw or not re.search(r"\b(?:BOOTP/DHCP|DHCPv?6|DHCP)\b", raw, re.I):
        return None
    first = lines[0] if lines else ""
    timestamp_match = re.match(r"^(\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d(?:\.\d+)?)\s*(.*)$", first)
    timestamp = timestamp_match.group(1) if timestamp_match else ""
    header = timestamp_match.group(2) if timestamp_match else first
    interface = ""
    direction = ""
    for pattern in (r"^(\S+)\s+(In|Out)\s+(?:IP6?\s+)", r"^(\S+)\s+(?:IP6?\s+)"):
        match = re.search(pattern, header)
        if match:
            interface = match.group(1)
            direction = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
            break
    endpoint_header = re.sub(rf"^{re.escape(interface)}\s+(?:(?:In|Out)\s+)?", "", header) if interface else header
    endpoint = re.search(r"(?:IP6?\s+)?(.+?)\s+>\s+(.+?):\s+(?:BOOTP/DHCP|DHCPv?6?|DHCP)\b", endpoint_header, re.I)
    source = endpoint.group(1).strip() if endpoint else ""
    destination = endpoint.group(2).strip() if endpoint else ""
    decoded = "\n".join(lines)
    message_match = re.search(r"DHCP[- ]Message[^\n]*?:\s*([A-Za-z0-9_-]+)", decoded, re.I)
    if message_match:
        message = message_match.group(1).upper()
    else:
        message_match = re.search(r"\bDHCPv?6[^\n]*?\b(SOLICIT|ADVERTISE|REQUEST|CONFIRM|RENEW|REBIND|REPLY|RELEASE|DECLINE|RECONFIGURE|INFORMATION-REQUEST)\b", decoded, re.I)
        if not message_match:
            message_match = re.search(r"\bBOOTP/DHCP,\s*([A-Za-z0-9_-]+)", decoded, re.I)
        message = message_match.group(1).upper() if message_match else "DHCP"
    mac_match = re.search(r"(?:Request from|Client-Ethernet-Address)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})", decoded, re.I)
    xid_match = re.search(r"\bxid\s+(0x[0-9a-f]+)", decoded, re.I)
    options = []
    for line in lines[1:]:
        cleaned = line.strip()
        if cleaned and cleaned not in options:
            options.append(cleaned)
    return {
        "timestamp": timestamp,
        "interface": interface or "—",
        "direction": direction,
        "message": message,
        "source": source,
        "destination": destination,
        "client_mac": mac_match.group(1).lower() if mac_match else "",
        "xid": xid_match.group(1) if xid_match else "",
        "details": "\n".join(options) or decoded,
        "raw": raw,
    }


class DHCPStreamWorker(threading.Thread):
    """Stream decoded DHCP traffic from a remote tcpdump process over SSH.

    The reader groups tcpdump continuation lines into packets, parses each group with :func:`parse_dhcp_packet`, and posts packet/status/error events to the GUI queue. It owns only its SSH channel; the shared SSH client remains managed by :class:`SSHRemote`."""

    COMMAND = "tcpdump -l -n -tttt -e -vvv -i any 'udp and (port 67 or port 68 or port 546 or port 547)' 2>&1"

    def __init__(self, remote: "SSHRemote", events: queue.Queue, stop_event: threading.Event) -> None:
        """Initialize the remote stream reader with the SSH manager, GUI event queue, and cancellation event."""
        super().__init__(daemon=True, name="dhcp-tcpdump")
        self.remote, self.events, self.stop_event = remote, events, stop_event
        self.channel = None

    def run(self) -> None:
        """Open a remote tcpdump shell channel, assemble complete packet records, and publish decoded packets until stopped or disconnected."""
        pending = ""
        packet_lines: list[str] = []
        last_chunk_at = time.monotonic()
        try:
            client = self.remote._get_client()
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("SSH-Transport ist nicht aktiv.")
            self.channel = transport.open_session(timeout=8)
            self.channel.exec_command(self.COMMAND)
            self.events.put(("dhcp_status", "__RUNNING__"))
            while not self.stop_event.is_set() and not self.channel.exit_status_ready():
                chunk = b""
                if self.channel.recv_ready():
                    chunk += self.channel.recv(65536)
                if self.channel.recv_stderr_ready():
                    chunk += self.channel.recv_stderr(65536)
                if not chunk:
                    if packet_lines and time.monotonic() - last_chunk_at >= 0.15:
                        if pending.strip():
                            packet_lines.append(pending.strip())
                            pending = ""
                        self._publish(packet_lines)
                        packet_lines = []
                    time.sleep(0.03)
                    continue
                last_chunk_at = time.monotonic()
                pending += chunk.decode("utf-8", errors="replace")
                while "\n" in pending:
                    line, pending = pending.split("\n", 1)
                    if re.match(r"^\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d", line):
                        self._publish(packet_lines)
                        packet_lines = [line]
                    elif packet_lines:
                        packet_lines.append(line)
                    elif "tcpdump:" in line.lower() or "listening on" in line.lower():
                        self.events.put(("dhcp_status", line.strip()))
            if pending.strip():
                packet_lines.append(pending.strip())
            self._publish(packet_lines)
            if not self.stop_event.is_set():
                code = self.channel.recv_exit_status()
                raise RuntimeError(f"tcpdump wurde beendet (Exit-Code {code}).")
        except Exception as exc:
            if not self.stop_event.is_set():
                self.events.put(("dhcp_error", f"DHCP-Aufzeichnung fehlgeschlagen · {type(exc).__name__}: {exc}"))
        finally:
            if self.channel is not None:
                try: self.channel.close()
                except Exception: pass

    def _publish(self, lines: list[str]) -> None:
        """Convert accumulated tcpdump lines into one packet event and clear the packet buffer for the next record."""
        packet = parse_dhcp_packet(lines)
        if packet is not None:
            self.events.put(("dhcp_packet", packet))


class PingWorker(threading.Thread):
    """Run one independent periodic probe loop for a destination.

    A worker emits a result as soon as each local subprocess or remote request completes. Its stop event makes interval waits interruptible, while a shared semaphore can cap local process concurrency. Remote workers share an :class:`SSHRemote` dispatcher rather than opening a connection per probe."""

    def __init__(self, target: str, events: queue.Queue, stop_event: threading.Event,
                 interval: float, timeout: float, process_gate: threading.BoundedSemaphore | None = None,
                 ssh_remote: "SSHRemote | None" = None) -> None:
        """Bind one destination to its timing, cancellation, local-process limit, and optional shared SSH backend."""
        super().__init__(daemon=True, name=f"ping-{target}")
        self.target, self.events, self.stop_event = target, events, stop_event
        self.interval, self.timeout = interval, timeout
        self.process_gate = process_gate
        self.ssh_remote = ssh_remote
        self.mac_address = ""

    def run(self) -> None:
        """Run the target probe loop and enqueue a result immediately after each completion.

Waits are interruptible, and the next per-target interval begins after the preceding probe finishes."""
        while not self.stop_event.is_set():
            latency, status = self.probe()
            if self.ssh_remote is None:
                timestamp = datetime.now().astimezone()
                self.events.put(("sample", self.target, timestamp, latency, status, self.mac_address))
            # Start the interval after finishing this probe. Time spent waiting for
            # a process slot must not let this target immediately reacquire it and
            # starve targets still waiting for their first sample.
            self.stop_event.wait(self.interval)

    def probe(self) -> tuple[float | None, str]:
        """Execute one local or remote ping and return its latency (if successful) and normalized result label."""
        gate_acquired = False
        if self.process_gate is not None:
            while not self.stop_event.is_set():
                gate_acquired = self.process_gate.acquire(timeout=0.2)
                if gate_acquired:
                    break
            if not gate_acquired:
                return None, "Abgebrochen"
        system = platform.system().lower()
        args = ["ping", "-n", "-w", str(int(self.timeout * 1000)), "-c", "1", self.target] if system != "windows" else ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), self.target]
        begin = time.perf_counter()
        try:
            if self.ssh_remote is not None:
                def publish(target, result):
                    """Forward one asynchronous ping completion to the request callback.

The callback receives the target and normalized result tuple; callback exceptions are contained so the SSH dispatcher reader remains alive."""
                    latency, status, mac = result
                    if mac:
                        self.mac_address = mac
                    self.events.put(("sample", target, datetime.now().astimezone(), latency, status, mac or self.mac_address))
                latency, status, mac = self.ssh_remote.ping(self.target, self.timeout, callback=publish)
                if mac:
                    self.mac_address = mac
                return latency, status
            # Windows ping output uses the active console code page and may contain
            # bytes that Python's locale decoder cannot decode. Keep subprocess I/O
            # as bytes so its internal reader threads cannot fail with UnicodeDecodeError.
            result = subprocess.run(args, capture_output=True, text=False, timeout=self.timeout + 1,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            elapsed = (time.perf_counter() - begin) * 1000
            # Windows' ping.exe writes in the OEM code page (typically CP850).
            # Decode accordingly so German unreachable messages remain detectable.
            output = (result.stdout or b"").decode("cp850", errors="replace")
            output += (result.stderr or b"").decode("cp850", errors="replace")
            output = output.casefold()
            unreachable = (
                "destination host unreachable", "destination net unreachable",
                "zielhost nicht erreichbar", "zielnetz nicht erreichbar",
                "request timed out", "zeitüberschreitung", "general failure",
                "allgemeiner fehler",
            )
            if any(message in output for message in unreachable):
                return None, "Zeitüberschreitung" if ("timed out" in output or "zeitüberschreitung" in output or "request timed out" in output) else "Ziel nicht erreichbar"
            if result.returncode == 0 and re.search(r"(?:bytes\s*=|bytes\s+from|bytes\s+von)\s*\d*", output):
                # Prefer the RTT reported by ping.exe. Use process timing only when
                # the localized response line has no parseable time field.
                match = re.search(r"(?:time|zeit)[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", output)
                return (float(match.group(1).replace(",", ".")) if match else elapsed), "OK"
            if result.returncode != 0:
                return None, "Zeitüberschreitung" if ("timed out" in output or "zeitüberschreitung" in output or "request timed out" in output) else "Ziel nicht erreichbar"
            return None, "Keine gültige Antwort"
        except (OSError, subprocess.TimeoutExpired):
            return None, "Zeitüberschreitung"
        finally:
            if gate_acquired:
                self.process_gate.release()


class SSHRemote:
    """Reuse one SSH connection to dispatch many concurrent remote probes.

    A small pool of persistent shell channels accepts batches of asynchronous ping commands. Request IDs associate completion markers with targets, allowing each fast reply to be delivered immediately even when another target is still waiting for its timeout. The same object also runs one-shot commands for SSH checks and interface discovery."""

    BATCH_SIZE = 32
    BATCH_WORKERS = 2

    def __init__(self, host: str, username: str, password: str, port: int = 22, channel_limit: int = 2,
                 result_callback=None) -> None:
        """Configure SSH credentials, connection and channel synchronization, asynchronous dispatch state, and the optional completion callback."""
        self.host, self.username, self.password, self.port = host.strip(), username.strip(), password, port
        self.result_callback = result_callback
        self._client = None
        self._lock = threading.RLock()
        self._channel_gate = threading.BoundedSemaphore(max(1, channel_limit))
        self._closed = threading.Event()
        self._dispatcher_lock = threading.RLock()
        self._dispatchers: list[dict] = []
        self._request_lock = threading.RLock()
        self._pending_requests: dict[int, dict] = {}
        self._next_request_id = 0
        self._remote_slots = threading.BoundedSemaphore(self.BATCH_SIZE * self.BATCH_WORKERS)

    def _get_client(self):
        """Create or return the shared Paramiko client, establishing the SSH transport on first use."""
        import paramiko
        with self._lock:
            if self._client is None or self._client.get_transport() is None or not self._client.get_transport().is_active():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=self.host, port=self.port, username=self.username, password=self.password,
                               timeout=6, banner_timeout=6, auth_timeout=8, allow_agent=False, look_for_keys=False)
                self._client = client
            return self._client

    def command(self, command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        """Execute a bounded, one-shot remote shell command and return its exit status, standard output, and standard error."""
        with self._channel_gate:
            client = self._get_client()
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("SSH-Transport ist nicht aktiv.")
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        # Drain both SSH streams while the remote command is running. Waiting for
        # stdout.read() until process exit delayed every result to the slowest ping
        # in the batch. Read stdout incrementally and publish a target immediately
        # when its result block is complete.
        out_parts: list[str] = []
        err_parts: list[str] = []
        pending = ""
        completed: set[int] = set()
        stdout_channel = stdout.channel
        stderr_channel = stderr.channel
        deadline = time.monotonic() + max(1.0, timeout)
        marker = re.compile(r"__PPLOT_START_(\d+)__(\d+)\s*\n(.*?)\n__PPLOT_NEIGH_\1__\s*\n(.*?)\n__PPLOT_END_\1__", re.S)
        while not stdout_channel.exit_status_ready() or stdout_channel.recv_ready() or stderr_channel.recv_stderr_ready():
            got_data = False
            while stdout_channel.recv_ready():
                chunk = stdout_channel.recv(65536).decode("utf-8", errors="replace")
                out_parts.append(chunk); pending += chunk; got_data = True
                for found in marker.finditer(pending):
                    index = int(found.group(1))
                    if index in completed:
                        continue
                    completed.add(index)
                    self._publish_block(index, found.group(2), found.group(3), found.group(4))
                if len(pending) > 250_000:
                    pending = pending[-100_000:]
            while stderr_channel.recv_stderr_ready():
                err_parts.append(stderr_channel.recv_stderr(65536).decode("utf-8", errors="replace")); got_data = True
            if time.monotonic() > deadline:
                stdout_channel.close()
                raise TimeoutError("Zeitüberschreitung beim Lesen der SSH-Antwort.")
            if not got_data:
                time.sleep(0.005)
        out = "".join(out_parts)
        err = "".join(err_parts)
        return stdout_channel.recv_exit_status(), out, err

    def test(self) -> str:
        """Verify SSH authentication and return the remote hostname for the connection test dialog."""
        rc, output, error = self.command("hostname", timeout=8)
        hostname = output.strip()
        if rc != 0 or not hostname:
            details = error.strip() or output.strip() or f"Remote-Befehl endete mit Status {rc}."
            raise RuntimeError(f"SSH-Verbindung steht, aber der hostname-Test schlug fehl: {details}")
        return hostname

    def ping(self, target: str, timeout: float, callback=None) -> tuple[float | None, str, str]:
        """Submit a ping request to the persistent remote dispatcher and return its completion result.

When a callback is supplied, the request can be delivered asynchronously so the caller does not wait for the ping timeout."""
        if self._closed.is_set():
            return None, "SSH-Verbindung beendet", ""
        if not self._remote_slots.acquire(timeout=max(2.0, timeout + 2.0)):
            return None, "Zu viele parallele SSH-Pings", ""
        with self._request_lock:
            self._next_request_id += 1
            request_id = self._next_request_id
            request = {"target": target, "timeout": timeout, "ready": threading.Event(), "result": None,
                       "callback": callback, "published": False}
            self._pending_requests[request_id] = request
        try:
            dispatchers = self._ensure_dispatchers()
            dispatcher = dispatchers[(request_id - 1) % len(dispatchers)]
            wait = max(1, int(timeout + 0.999))
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", target):
                raise ValueError("Ungültiges Ping-Ziel.")
            dispatcher["channel"].sendall(f"PING {request_id} {wait} {target}\n".encode("ascii"))
        except Exception as exc:
            self._publish_request(request_id, (None, f"SSH-Fehler: {exc}", ""))
        if not request["ready"].wait(max(30.0, timeout + 15.0)):
            self._publish_request(request_id, (None, "SSH-Antwort-Zeitüberschreitung", ""))
        return request["result"] or (None, "SSH-Ping fehlgeschlagen", "")

    def _ensure_dispatchers(self) -> list[dict]:
        """Create the configured number of persistent shell dispatchers, or return the dispatchers already running."""
        with self._dispatcher_lock:
            active = [d for d in self._dispatchers
                      if not d["channel"].closed and not d["channel"].exit_status_ready()]
            if len(active) == self.BATCH_WORKERS:
                self._dispatchers = active
                return active
            for dispatcher in self._dispatchers:
                try: dispatcher["channel"].close()
                except Exception: pass
            self._dispatchers = []
            script = "\n".join([
                'tmpdir=$(mktemp -d) || exit 70',
                'trap \'rm -rf "$tmpdir"\' EXIT',
                "while IFS=' ' read -r op rid wait target; do",
                '  [ "$op" = QUIT ] && break',
                '  [ "$op" = PING ] || continue',
                '  (ping -n -c 1 -W "$wait" "$target" >"$tmpdir/out$rid" 2>&1; rc=$?; {',
                '    printf "__PPLOT_START_%s__%s\\n" "$rid" "$rc"',
                '    cat "$tmpdir/out$rid"',
                '    printf "\\n__PPLOT_NEIGH_%s__\\n" "$rid"',
                '    ip neigh show "$target" 2>/dev/null',
                '    printf "\\n__PPLOT_END_%s__\\n" "$rid"',
                '  } >"$tmpdir/block$rid"; cat "$tmpdir/block$rid") </dev/null &',
                'done',
            ])
            client = self._get_client()
            try:
                for index in range(self.BATCH_WORKERS):
                    with self._channel_gate:
                        _stdin, _stdout, _stderr = client.exec_command(script, timeout=8)
                    # Keep all ChannelFile wrappers alive: collecting stdin would
                    # close its writer and send EOF to the persistent shell loop.
                    dispatcher = {"channel": _stdout.channel, "stdin": _stdin,
                                  "stdout": _stdout, "stderr": _stderr,
                                  "index": index, "pending": ""}
                    reader = threading.Thread(target=self._read_dispatcher, args=(dispatcher,),
                                              name=f"ssh-stream-{index + 1}", daemon=True)
                    dispatcher["reader"] = reader
                    self._dispatchers.append(dispatcher)
                    reader.start()
            except Exception:
                for dispatcher in self._dispatchers:
                    try: dispatcher["channel"].close()
                    except Exception: pass
                self._dispatchers = []
                raise
            return self._dispatchers

    def _read_dispatcher(self, dispatcher: dict) -> None:
        """Read one dispatcher stream, split response blocks by request ID, and route completed requests to the result publisher."""
        channel = dispatcher["channel"]
        marker = re.compile(r"__PPLOT_START_(\d+)__(\d+)\s*\n(.*?)\n__PPLOT_NEIGH_\1__\s*\n(.*?)\n__PPLOT_END_\1__", re.S)
        try:
            while not self._closed.is_set() and not channel.closed:
                got_data = False
                while channel.recv_ready():
                    dispatcher["pending"] += channel.recv(65536).decode("utf-8", errors="replace")
                    got_data = True
                    for found in marker.finditer(dispatcher["pending"]):
                        self._publish_block(int(found.group(1)), found.group(2), found.group(3), found.group(4))
                    if len(dispatcher["pending"]) > 250_000:
                        dispatcher["pending"] = dispatcher["pending"][-100_000:]
                while channel.recv_stderr_ready():
                    channel.recv_stderr(65536)
                    got_data = True
                if channel.exit_status_ready():
                    raise RuntimeError(f"SSH-Ping-Shell {dispatcher['index'] + 1} wurde beendet.")
                if not got_data:
                    time.sleep(0.005)
        except Exception as exc:
            if not self._closed.is_set():
                message = f"SSH-Streamfehler: {exc}"
                with self._request_lock:
                    failed = [rid for rid, req in self._pending_requests.items()
                              if (rid - 1) % self.BATCH_WORKERS == dispatcher["index"]]
                for request_id in failed:
                    self._publish_request(request_id, (None, message, ""))

    def _publish_request(self, request_id: int, result: tuple[float | None, str, str]) -> None:
        """Deliver one parsed ping result to the registered callback or synchronous waiter."""
        with self._request_lock:
            request = self._pending_requests.get(request_id)
            if request is None or request["published"]:
                return
            request["published"] = True
            request["result"] = result
            del self._pending_requests[request_id]
        callback = request.get("callback") or self.result_callback
        try:
            if callback is not None:
                callback(request["target"], result)
        finally:
            request["ready"].set()
            self._remote_slots.release()

    def _publish_block(self, request_id: int, ping_rc: str, ping_output: str, neighbor_output: str) -> None:
        """Interpret a remote result block, including ping outcome and neighbor-table MAC information, then complete its request."""
        with self._request_lock:
            request = self._pending_requests.get(request_id)
        if request is None:
            return
        mac_match = MAC_RE.search(neighbor_output)
        mac = mac_match.group(0).lower() if mac_match else ""
        combined = ping_output.casefold()
        if "destination host unreachable" in combined or "destination net unreachable" in combined:
            result = (None, "Ziel nicht erreichbar", mac)
        else:
            match = re.search(r"time[=<]\s*(<?)(\d+(?:\.\d+)?)\s*ms", ping_output, re.I)
            if match:
                latency = float(match.group(2))
                if match.group(1) == "<": latency = min(latency, 0.5)
                result = (latency, "OK", mac)
            elif re.search(r"\d+ bytes from ", ping_output, re.I) or "0% packet loss" in combined:
                result = (None, "Antwort ohne Latenzwert", mac)
            elif "100% packet loss" in combined or "0 packets received" in combined or int(ping_rc or 1) != 0:
                result = (None, "Zeitüberschreitung", mac)
            else:
                result = (None, "Keine gültige Antwort", mac)
        self._publish_request(request_id, result)

    def close(self) -> None:
        """Stop dispatcher readers, close shell channels and the SSH client, and release pending waiters safely."""
        if self._closed.is_set():
            return
        self._closed.set()
        with self._dispatcher_lock:
            for dispatcher in self._dispatchers:
                try:
                    dispatcher["channel"].sendall(b"QUIT\n")
                    dispatcher["channel"].close()
                except Exception:
                    pass
            self._dispatchers = []
        with self._request_lock:
            pending = list(self._pending_requests)
        for request_id in pending:
            self._publish_request(request_id, (None, "SSH-Verbindung beendet", ""))
        with self._lock:
            if self._client is not None:
                self._client.close()
                self._client = None


class PingeeApp:
    """Own all application state and Tk widgets for the pingee desktop monitor.

Background workers communicate through a thread-safe event queue; only the Tk main thread updates widgets. This class coordinates target workers, in-memory histories, SSH tools, translations, child windows, filters, tables, and graph rendering."""
    def __init__(self, root: tk.Tk) -> None:
        """Initialize shared measurement state, Tk variables, worker registries, histories, translation state, and the main window."""
        self.root = root
        root.title(APP_TITLE)
        root.geometry("1440x900")
        root.minsize(900, 560)
        self.language = "EN"
        self.language_choice = tk.StringVar(value=LANGUAGE_NAMES["EN"])
        self._localized_widget_sources: dict[tk.Widget, str] = {}
        self._localized_heading_sources: dict[tuple[ttk.Treeview, str], str] = {}
        self._localized_tab_sources: dict[tuple[ttk.Notebook, str], str] = {}
        self._localized_combo_sources: dict[ttk.Combobox, tuple[str, ...]] = {}
        self.events: queue.Queue = queue.Queue()
        self.workers: dict[str, tuple[threading.Event, PingWorker]] = {}
        self.process_gate: threading.BoundedSemaphore | None = None
        self.ssh_remote: SSHRemote | None = None
        self.samples: dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_POINTS))
        self.labels: dict[str, str] = {}
        self.macs: dict[str, str] = {}
        self.selected: set[str] = set()
        self.run_offline: set[str] = set()
        self.run_ever_online: set[str] = set()
        self.run_started_at: datetime | None = None
        self.first_round_seconds: float | None = None
        self.last_seen: dict[str, datetime | None] = {}
        self.large_mode = False
        self.large_threshold = 80
        self.filter_text = tk.StringVar()
        self.hide_run_offline = tk.BooleanVar(value=False)
        self.hide_current_offline = tk.BooleanVar(value=False)
        self.running = False
        self.interval = tk.DoubleVar(value=DEFAULT_INTERVAL)
        self.timeout = tk.DoubleVar(value=1.0)
        self.concurrency = tk.IntVar(value=16)
        self.use_ssh = tk.BooleanVar(value=False)
        self.ssh_host = tk.StringVar(value="")
        self.ssh_username = tk.StringVar(value="")
        self.ssh_password = tk.StringVar(value="")
        self._ssh_auto_enable_after_id = None
        self.ssh_test_button: ttk.Button | None = None
        self.window_mode = tk.StringVar(value="Last 5 minutes")
        self.relative_amount = tk.StringVar(value="5")
        self.relative_unit = tk.StringVar(value="Minutes")
        self.custom_from = tk.StringVar()
        self.custom_to = tk.StringVar()
        self.last_loss: dict[str, datetime | None] = {}
        self.sort_reverse: dict[str, bool] = {}
        self.plot_window: tk.Toplevel | None = None
        self.plot_detail = tk.StringVar(value="Hover over a graph point to see its details.")
        self.plot_tooltip: tk.Frame | None = None
        self.plot_tooltip_canvas: tk.Canvas | None = None
        self.plot_tooltip_window_id: int | None = None
        self.plot_canvases: list[tk.Canvas] = []
        self.plot_points: dict[tk.Canvas, list[tuple[float, float, str, datetime, float | None, str]]] = {}
        self._plot_redraw_after_id = None
        self._drain_after_id = None
        self.neighbor_window: tk.Toplevel | None = None
        self.neighbor_tree: ttk.Treeview | None = None
        self.neighbor_history_tree: ttk.Treeview | None = None
        self.neighbor_changes_tree: ttk.Treeview | None = None
        self.neighbor_monitor_status = tk.StringVar(value="Monitoring stopped")
        self.neighbor_interval = tk.DoubleVar(value=10.0)
        self.neighbor_monitor_thread: threading.Thread | None = None
        self.neighbor_monitor_stop: threading.Event | None = None
        self.neighbor_remote: SSHRemote | None = None
        self.neighbor_current: dict[str, dict[str, str]] = {}
        self.neighbor_latest: dict[str, dict[str, str]] = {}
        self.neighbor_first_seen: dict[str, datetime] = {}
        self.neighbor_last_seen: dict[str, datetime] = {}
        self.neighbor_change_flags: dict[str, list[str]] = defaultdict(list)
        self.neighbor_event_filters = {
            "presence": tk.BooleanVar(value=True),
            "loss": tk.BooleanVar(value=True),
            "metadata": tk.BooleanVar(value=True),
            "state": tk.BooleanVar(value=False),
        }
        self.neighbor_snapshots: deque = deque(maxlen=MAX_NEIGHBOR_HISTORY)
        self.neighbor_observations: deque = deque(maxlen=MAX_NEIGHBOR_HISTORY)
        self.neighbor_changes: deque = deque(maxlen=MAX_NEIGHBOR_HISTORY)
        self.neighbor_snapshot_count = 0
        self.dhcp_window: tk.Toplevel | None = None
        self.dhcp_remote: SSHRemote | None = None
        self.dhcp_capture: DHCPStreamWorker | None = None
        self.dhcp_capture_stop: threading.Event | None = None
        self.dhcp_packets: deque = deque(maxlen=MAX_NEIGHBOR_HISTORY)
        self.dhcp_interfaces: dict[str, list[str]] = {}
        self.dhcp_interface_list: tk.Listbox | None = None
        self.dhcp_packet_tree: ttk.Treeview | None = None
        self.dhcp_detail_text: tk.Text | None = None
        self.dhcp_capture_button: ttk.Button | None = None
        self.dhcp_load_button: ttk.Button | None = None
        self.dhcp_loading = False
        self.dhcp_status = tk.StringVar(value="Loading network interfaces …")
        self.panel_visibility = {
            "targets": tk.BooleanVar(value=True),
            "graph": tk.BooleanVar(value=True),
            "measurements": tk.BooleanVar(value=True),
        }
        self.toolbar_visibility = {
            key: tk.BooleanVar(value=key not in {"files", "windows"})
            for key in ("settings", "ssh", "filter", "files", "windows")
        }
        self.detached_target_views: list[dict] = []
        self.detached_data_trees: list[ttk.Treeview] = []
        self.status = tk.StringVar(value="Ready · add targets and start monitoring")
        self._build_ui()
        self.interval.trace_add("write", self._worker_timing_changed)
        self.timeout.trace_add("write", self._worker_timing_changed)
        self._drain_after_id = self.root.after(50, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _translation_index(self) -> int:
        """Return the index of the active language in the translation tuple catalog."""
        return LANGUAGE_CHOICES.index(self.language)

    def tr(self, source: str) -> str:
        """Translate a German source label into the currently selected UI language, falling back to the source text when no entry exists."""
        translations = TRANSLATIONS.get(source)
        return translations[self._translation_index()] if translations else source

    def trf(self, key: str, **values) -> str:
        """Format a localized status message by key, interpolating the supplied dynamic values."""
        translations = STATUS_TRANSLATIONS.get(key)
        if not translations:
            return key.format(**values)
        return translations[self._translation_index()].format(**values)

    @staticmethod
    def _locale_source(value: str) -> str:
        """Map a displayed localized value back to its canonical catalog key so controls can be retranslated without losing their selection."""
        if value in TRANSLATIONS:
            return value
        for source, translations in TRANSLATIONS.items():
            if value in translations:
                return source
        return value

    def _change_language(self, _event=None) -> None:
        """Read the selected language and reapply translations to the root window and all open child windows."""
        choice = self.language_choice.get()
        self.language = next((code for code, name in LANGUAGE_NAMES.items() if name == choice), "EN")
        self._apply_language()

    def _apply_language(self) -> None:
        """Update widget labels, table headings, tabs, combobox values, window titles, time selectors, and graph labels for the selected language."""
        self.root.title("pingee · " + self.tr("Netzwerkmonitor"))
        mode_source = self._locale_source(self.window_mode.get())
        unit_source = self._locale_source(self.relative_unit.get())

        def visit(parent: tk.Misc) -> None:
            """Recursively apply the active language to a widget subtree.

Remember canonical source strings so repeated language changes do not translate an already translated label as if it were a new source."""
            for widget in parent.winfo_children():
                try:
                    value = widget.cget("text")
                except (tk.TclError, TypeError):
                    value = None
                if isinstance(value, str) and value:
                    source = self._localized_widget_sources.get(widget, self._locale_source(value))
                    if source in TRANSLATIONS:
                        self._localized_widget_sources[widget] = source
                        try: widget.configure(text=self.tr(source))
                        except tk.TclError: pass
                if isinstance(widget, ttk.Treeview):
                    for column in widget["columns"]:
                        heading = widget.heading(column).get("text", "")
                        key = (widget, column)
                        source = self._localized_heading_sources.get(key, self._locale_source(heading))
                        if source in TRANSLATIONS:
                            self._localized_heading_sources[key] = source
                            widget.heading(column, text=self.tr(source))
                if isinstance(widget, ttk.Notebook):
                    for tab in widget.tabs():
                        title = widget.tab(tab, "text")
                        key = (widget, tab)
                        source = self._localized_tab_sources.get(key, self._locale_source(title))
                        if source in TRANSLATIONS:
                            self._localized_tab_sources[key] = source
                            widget.tab(tab, text=self.tr(source))
                if isinstance(widget, ttk.Combobox) and widget is not getattr(self, "language_combo", None):
                    values = tuple(widget.cget("values"))
                    sources = self._localized_combo_sources.get(widget, tuple(self._locale_source(v) for v in values))
                    self._localized_combo_sources[widget] = sources
                    widget.configure(values=tuple(self.tr(source) for source in sources))
                if isinstance(widget, (tk.Toplevel, tk.Tk)):
                    try:
                        title = widget.title()
                        source = self._localized_widget_sources.get(widget, self._locale_source(title))
                        if source in TRANSLATIONS:
                            self._localized_widget_sources[widget] = source
                            widget.title(self.tr(source))
                    except tk.TclError: pass
                visit(widget)

        visit(self.root)
        self.window_mode.set(self.tr(mode_source) if mode_source in TRANSLATIONS else mode_source)
        self.relative_unit.set(self.tr(unit_source) if unit_source in TRANSLATIONS else unit_source)
        self._refresh_run_button()
        self._redraw_plots()

    def _build_ui(self) -> None:
        """Construct the main window, toolbar sections, target editor, target table, graph, measurement table, and responsive split panes."""
        self.colors = {
            "page": "#f3f5f9", "surface": "#ffffff", "surface_alt": "#f7f9fc",
            "ink": "#17263c", "muted": "#66758b", "line": "#d9e0ea",
            "accent": "#2563eb", "accent_hover": "#1d4ed8", "danger": "#c2414b",
            "success": "#138a69", "plot": "#fbfcfe",
        }
        self.root.configure(bg=self.colors["page"])
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=self.colors["page"])
        style.configure("Card.TFrame", background=self.colors["surface"])
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), background=self.colors["page"], foreground=self.colors["ink"])
        style.configure("Sub.TLabel", font=("Segoe UI", 9), background=self.colors["page"], foreground=self.colors["muted"])
        style.configure("Section.TLabel", font=("Segoe UI", 11, "bold"), background=self.colors["surface"], foreground=self.colors["ink"])
        style.configure("Muted.TLabel", font=("Segoe UI", 9), background=self.colors["surface"], foreground=self.colors["muted"])
        style.configure("TLabel", background=self.colors["page"], foreground=self.colors["ink"], font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI", 9), padding=(10, 6), borderwidth=0, background="#e8edf5", foreground=self.colors["ink"])
        style.map("TButton", background=[("disabled", "#edf0f5"), ("pressed", "#d8e0eb"), ("active", "#dde5ef")], foreground=[("disabled", "#9aa5b4")])
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"), padding=(14, 7), background=self.colors["accent"], foreground="white")
        style.map("Accent.TButton", background=[("disabled", "#9bb8f3"), ("pressed", self.colors["accent_hover"]), ("active", self.colors["accent_hover"])], foreground=[("disabled", "#f4f7ff")])
        style.configure("Danger.TButton", font=("Segoe UI", 9, "bold"), padding=(11, 7), background="#fcebed", foreground=self.colors["danger"])
        style.map("Danger.TButton", background=[("pressed", "#f5d4d8"), ("active", "#f8dfe2")])
        style.configure("TEntry", padding=(7, 5), fieldbackground=self.colors["surface"], bordercolor=self.colors["line"], lightcolor=self.colors["line"], darkcolor=self.colors["line"])
        style.map("TEntry", bordercolor=[("focus", self.colors["accent"])], lightcolor=[("focus", self.colors["accent"])], darkcolor=[("focus", self.colors["accent"])])
        style.configure("TCombobox", padding=(6, 4), fieldbackground=self.colors["surface"], background=self.colors["surface"], bordercolor=self.colors["line"])
        style.map("TCombobox", fieldbackground=[("readonly", self.colors["surface"])], selectbackground=[("readonly", self.colors["surface"])], selectforeground=[("readonly", self.colors["ink"])])
        style.configure("TSpinbox", padding=(5, 3), fieldbackground=self.colors["surface"], bordercolor=self.colors["line"])
        style.configure("TCheckbutton", background=self.colors["page"], foreground=self.colors["ink"], font=("Segoe UI", 9), padding=(3, 3))
        style.map("TCheckbutton", foreground=[("disabled", "#9aa5b4")], background=[("active", self.colors["page"])])
        style.configure("Card.TCheckbutton", background=self.colors["surface"], foreground=self.colors["ink"], font=("Segoe UI", 9), padding=(3, 3))
        style.configure("Treeview", rowheight=25, font=("Segoe UI", 9), background=self.colors["surface"], fieldbackground=self.colors["surface"], foreground=self.colors["ink"], borderwidth=0)
        style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", self.colors["ink"])])
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#eef2f7", foreground="#40516a", padding=(8, 7), relief="flat")
        style.map("Treeview.Heading", background=[("active", "#e3e9f2")])
        style.configure("TNotebook", background=self.colors["page"], borderwidth=0, tabmargins=(2, 4, 2, 0))
        style.configure("TNotebook.Tab", padding=(12, 7), font=("Segoe UI", 9), background="#e9edf4", foreground=self.colors["muted"])
        style.map("TNotebook.Tab", background=[("selected", self.colors["surface"]), ("active", "#e1e8f2")], foreground=[("selected", self.colors["accent"])])

        top = ttk.Frame(self.root, padding=(22, 15, 22, 8)); top.pack(fill="x")
        title_block = ttk.Frame(top); title_block.pack(side="left", anchor="w")
        ttk.Label(title_block, text="Netzwerkmonitor", style="Title.TLabel").pack(anchor="w")
        ttk.Label(title_block, text="Kontinuierliche Latenz- und Erreichbarkeitsmessung · mehrere Ziele parallel", style="Sub.TLabel").pack(anchor="w", pady=(2, 0))
        toolbar = ttk.Frame(top); toolbar.pack(side="right", anchor="e", padx=(16, 0))
        self.run_button = ttk.Button(toolbar, text="▶  Start", style="Accent.TButton", command=self._toggle_run)
        self.run_button.pack(side="left", padx=(0, 8))
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=5)
        for key, title in (("settings", "Messparameter"), ("ssh", "SSH"), ("filter", "Filter"),
                           ("files", "Import / Export"), ("windows", "Fenster")):
            ttk.Checkbutton(toolbar, text=title, variable=self.toolbar_visibility[key],
                            command=lambda name=key: self._toggle_toolbar(name)).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=5)
        for key, title in (("targets", "Ziele"), ("graph", "Graph"), ("measurements", "Messwerte")):
            ttk.Checkbutton(toolbar, text=title, variable=self.panel_visibility[key],
                            command=lambda panel=key: self._toggle_main_panel(panel)).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=5)
        ttk.Label(toolbar, text="Language").pack(side="left", padx=(2, 4))
        self.language_combo = ttk.Combobox(toolbar, textvariable=self.language_choice, state="readonly", width=12,
                                           values=tuple(LANGUAGE_NAMES[code] for code in LANGUAGE_CHOICES))
        self.language_combo.pack(side="left")
        self.language_combo.bind("<<ComboboxSelected>>", self._change_language)

        self.settings_row = ttk.Frame(self.root, padding=(22, 0, 22, 7)); self.settings_row.pack(fill="x")
        ttk.Label(self.settings_row, text="Intervall (s)").pack(side="left")
        ttk.Spinbox(self.settings_row, from_=0.2, to=3600, increment=0.2, textvariable=self.interval, width=7).pack(side="left", padx=(6, 14))
        ttk.Label(self.settings_row, text="Timeout (s)").pack(side="left")
        ttk.Spinbox(self.settings_row, from_=0.2, to=30, increment=0.2, textvariable=self.timeout, width=7).pack(side="left", padx=(6, 14))
        ttk.Label(self.settings_row, text="Parallelprozesse").pack(side="left")
        ttk.Spinbox(self.settings_row, from_=1, to=512, increment=1, textvariable=self.concurrency, width=6).pack(side="left", padx=6)

        self.ssh_controls = ttk.Frame(self.root, padding=(22, 0, 22, 7)); self.ssh_controls.pack(fill="x")
        ttk.Checkbutton(self.ssh_controls, text="Pings per SSH ausführen", variable=self.use_ssh).pack(side="left")
        ttk.Label(self.ssh_controls, text="Firewall / SSH-Host").pack(side="left", padx=(12, 4))
        ttk.Entry(self.ssh_controls, textvariable=self.ssh_host, width=22).pack(side="left")
        ttk.Label(self.ssh_controls, text="Benutzer").pack(side="left", padx=(8, 4))
        ttk.Entry(self.ssh_controls, textvariable=self.ssh_username, width=14).pack(side="left")
        ttk.Label(self.ssh_controls, text="Passwort").pack(side="left", padx=(8, 4))
        ttk.Entry(self.ssh_controls, textvariable=self.ssh_password, show="•", width=18).pack(side="left")
        self.ssh_test_button = ttk.Button(self.ssh_controls, text="SSH testen", command=self.test_ssh)
        self.ssh_test_button.pack(side="left", padx=8)
        for credential in (self.ssh_host, self.ssh_username, self.ssh_password):
            credential.trace_add("write", self._ssh_credentials_changed)
        ttk.Button(self.ssh_controls, text="ARP / ip neigh überwachen", command=self.open_neighbor_monitor).pack(side="left", padx=3)
        ttk.Button(self.ssh_controls, text="DHCP tcpdump", command=self.open_dhcp_monitor).pack(side="left", padx=3)

        self.filters = ttk.Frame(self.root, padding=(22, 0, 22, 7)); self.filters.pack(fill="x")
        ttk.Label(self.filters, text="Ziel-Filter:").pack(side="left")
        entry = ttk.Entry(self.filters, textvariable=self.filter_text, width=28); entry.pack(side="left", padx=(6, 12))
        self.filter_text.trace_add("write", lambda *_: self._refresh_target_view())
        ttk.Checkbutton(self.filters, text="Dauerhaft offline ausblenden", variable=self.hide_run_offline, command=self._refresh_target_view).pack(side="left", padx=5)
        ttk.Checkbutton(self.filters, text="Aktuell offline ausblenden", variable=self.hide_current_offline, command=self._refresh_target_view).pack(side="left", padx=5)
        ttk.Button(self.filters, text="Alle", command=self.select_all).pack(side="right")
        ttk.Button(self.filters, text="Auswahl leeren", command=self.clear_selection).pack(side="right", padx=6)

        self.file_controls = ttk.Frame(self.root, padding=(22, 0, 22, 7)); self.file_controls.pack(fill="x")
        ttk.Button(self.file_controls, text="CSV importieren", command=self.import_csv).pack(side="left")
        ttk.Button(self.file_controls, text="Messwerte exportieren", command=self.export_data).pack(side="left", padx=7)
        self.file_controls.pack_forget()

        self.window_controls = ttk.Frame(self.root, padding=(22, 0, 22, 9)); self.window_controls.pack(fill="x")
        ttk.Button(self.window_controls, text="Ziele eigenes Fenster", command=self.open_detached_targets).pack(side="left", padx=(0, 4))
        ttk.Button(self.window_controls, text="Graph eigenes Fenster", command=self.open_plot_window).pack(side="left", padx=4)
        ttk.Button(self.window_controls, text="Messwerte eigenes Fenster", command=self.open_detached_measurements).pack(side="left", padx=4)
        self.window_controls.pack_forget()
        self._refresh_run_button()

        body = ttk.Panedwindow(self.root, orient="horizontal"); body.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.body_pane = body
        self.main_pane = body
        left = ttk.Frame(body, style="Card.TFrame", padding=12); right = ttk.Frame(body, style="Card.TFrame", padding=12)
        self.target_panel = left
        self.right_pane = ttk.Panedwindow(right, orient="vertical"); self.right_pane.pack(fill="both", expand=True)
        self.graph_panel = ttk.Frame(self.right_pane, style="Card.TFrame", padding=6)
        self.measurement_panel = ttk.Frame(self.right_pane, style="Card.TFrame", padding=6)
        self.right_pane.add(self.graph_panel, weight=3); self.right_pane.add(self.measurement_panel, weight=1)
        body.add(left, weight=1); body.add(right, weight=3)
        self.target_pane = ttk.Panedwindow(left, orient="vertical"); self.target_pane.pack(fill="both", expand=True)
        self.target_input_panel = ttk.Frame(self.target_pane, style="Card.TFrame", padding=4)
        self.target_table_panel = ttk.Frame(self.target_pane, style="Card.TFrame", padding=4)
        self.target_pane.add(self.target_input_panel, weight=1); self.target_pane.add(self.target_table_panel, weight=3)
        ttk.Label(self.target_input_panel, text="Ping-Ziele", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.target_input_panel, text="Adressen, Gerätelisten oder Netzwerktopologien einfügen.", wraplength=290, style="Muted.TLabel").pack(anchor="w", pady=(3, 7))
        self.input = tk.Text(self.target_input_panel, height=6, font=("Cascadia Mono", 9), relief="flat", bd=0, wrap="word",
                             bg="#fbfcfe", fg=self.colors["ink"], insertbackground=self.colors["accent"],
                             selectbackground="#cfe0ff", selectforeground=self.colors["ink"],
                             highlightthickness=1, highlightbackground=self.colors["line"], highlightcolor=self.colors["accent"], padx=8, pady=7)
        self.input.pack(fill="both", expand=True)
        self.input.insert("1.0", "8.8.8.8\n1.1.1.1\n")
        buttons = ttk.Frame(self.target_input_panel, style="Card.TFrame"); buttons.pack(fill="x", pady=7)
        ttk.Button(buttons, text="+ Ziele hinzufügen", style="Accent.TButton", command=self.add_from_text).pack(side="left")
        ttk.Button(buttons, text="Auswahl entfernen", style="Danger.TButton", command=self.remove_selected).pack(side="right")
        ttk.Label(self.target_table_panel, text="Zielstatus", style="Section.TLabel").pack(anchor="w", pady=(0, 7))
        cols = ("hostname", "target", "mac", "status", "last", "last_success", "loss", "last_loss")
        target_tree_frame = ttk.Frame(self.target_table_panel, style="Card.TFrame"); target_tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(target_tree_frame, columns=cols, show="headings", selectmode="extended", height=11)
        for c, title, width in [("hostname", "Hostname", 120), ("target", "IP-Adresse / Ziel", 115), ("mac", "MAC-Adresse", 130), ("status", "Status", 95), ("last", "Letzter Ping", 90), ("last_success", "Letzter Erfolg", 140), ("loss", "Verlust", 65), ("last_loss", "Letzter Verlust", 140)]:
            self.tree.heading(c, text=title, command=lambda col=c: self._sort_targets(col)); self.tree.column(c, width=width, anchor="w" if c in ("hostname", "target", "mac", "last_loss") else "center")
        target_y = ttk.Scrollbar(target_tree_frame, orient="vertical", command=self.tree.yview)
        target_x = ttk.Scrollbar(target_tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=target_y.set, xscrollcommand=target_x.set)
        self.tree.pack(side="top", fill="both", expand=True)
        target_y.pack(side="right", fill="y"); target_x.pack(side="bottom", fill="x")
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)
        self.tree.tag_configure("fail", foreground="#cc4751")
        self.tree.tag_configure("ok", foreground="#169b79")
        self.cards = tk.Canvas(self.target_table_panel, bg="white", highlightthickness=0)
        self.card_frame = ttk.Frame(self.cards, style="Card.TFrame")
        self.card_window = self.cards.create_window((0, 0), window=self.card_frame, anchor="nw")
        self.card_frame.bind("<Configure>", lambda _e: self.cards.configure(scrollregion=self.cards.bbox("all")))
        self.cards.bind("<Configure>", lambda e: self.cards.itemconfigure(self.card_window, width=e.width))
        self.card_vars: dict[str, tk.BooleanVar] = {}
        self.card_widgets: dict[str, dict[str, tk.Widget]] = {}
        ttk.Label(self.target_table_panel, text="Namen, IP-Adressen und Markdown-Tabellen werden erkannt.", wraplength=290, style="Muted.TLabel").pack(anchor="w")

        plot_head = ttk.Frame(self.graph_panel, style="Card.TFrame"); plot_head.pack(fill="x")
        ttk.Label(plot_head, text="Latenzverlauf", style="Section.TLabel").pack(side="left")
        ttk.Button(plot_head, text="⛶ Eigenes Fenster", command=self.open_plot_window).pack(side="right")
        time_controls = ttk.Frame(self.graph_panel, style="Card.TFrame"); time_controls.pack(fill="x", pady=(6, 0))
        ttk.Label(time_controls, text="Zeitraum").pack(side="left")
        range_box = ttk.Combobox(time_controls, textvariable=self.window_mode, state="readonly", width=20,
                                 values=("Gesamter Verlauf", "Letzte 30 Sekunden", "Letzte 5 Minuten", "Letzte 15 Minuten", "Letzte Stunde", "Letzte 6 Stunden", "Eigene relative Dauer", "Benutzerdefiniert"))
        range_box.pack(side="left", padx=6); range_box.bind("<<ComboboxSelected>>", lambda _e: self._redraw_plots())
        ttk.Label(time_controls, text="Von (YYYY-MM-DD HH:MM:SS)").pack(side="left", padx=(8, 3))
        ttk.Entry(time_controls, textvariable=self.custom_from, width=19).pack(side="left")
        ttk.Label(time_controls, text="Bis").pack(side="left", padx=(8, 3))
        ttk.Entry(time_controls, textvariable=self.custom_to, width=19).pack(side="left")
        ttk.Button(time_controls, text="Anwenden", command=self._redraw_plots).pack(side="left", padx=5)
        relative_controls = ttk.Frame(self.graph_panel, style="Card.TFrame"); relative_controls.pack(fill="x", pady=(4, 0))
        ttk.Label(relative_controls, text="Eigene relative Dauer: letzte").pack(side="left")
        ttk.Entry(relative_controls, textvariable=self.relative_amount, width=7).pack(side="left", padx=4)
        ttk.Combobox(relative_controls, textvariable=self.relative_unit, state="readonly", width=12,
                     values=("Sekunden", "Minuten", "Stunden")).pack(side="left")
        ttk.Button(relative_controls, text="Anwenden", command=self._apply_relative_window).pack(side="left", padx=5)
        self.plot = tk.Canvas(self.graph_panel, bg=self.colors["plot"], highlightthickness=1, highlightbackground=self.colors["line"], height=330)
        self.plot.pack(fill="both", expand=True, pady=(8, 12))
        self.plot_canvases.append(self.plot)
        self.plot.bind("<Configure>", lambda _e: self._redraw_plots())
        self.plot.bind("<Motion>", self._plot_mousemove)
        lower = self.measurement_panel
        ttk.Label(lower, text="Messwertverlauf · im Arbeitsspeicher", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        data_cols = ("time", "target", "mac", "latency", "state")
        self.data_tree = ttk.Treeview(lower, columns=data_cols, show="headings", height=8)
        for c, title, width in [("time", "Zeitstempel", 175), ("target", "Ziel", 150), ("mac", "MAC-Adresse", 135), ("latency", "Latenz (ms)", 100), ("state", "Ergebnis", 145)]:
            self.data_tree.heading(c, text=title); self.data_tree.column(c, width=width, anchor="w")
        scroll = ttk.Scrollbar(lower, orient="vertical", command=self.data_tree.yview); self.data_tree.configure(yscrollcommand=scroll.set)
        self.data_tree.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y")

        bar = ttk.Label(self.root, textvariable=self.status, anchor="w", padding=(22, 7), background="#e9edf4", foreground="#46566d", font=("Segoe UI", 9))
        bar.pack(fill="x", side="bottom")

        # Desktop-first keyboard shortcuts; all actions remain available in the toolbar.
        self.root.bind_all("<F5>", lambda _event: self.start())
        self.root.bind_all("<Shift-F5>", lambda _event: self.stop())
        self.root.bind_all("<Control-o>", lambda _event: self.import_csv())
        self.root.bind_all("<Control-s>", lambda _event: self.export_data())
        self.root.bind_all("<Control-f>", lambda _event: (entry.focus_set(), "break")[1])
        self.input.bind("<Control-Return>", lambda _event: (self.add_from_text(), "break")[1])
        self._apply_language()

    def _toggle_main_panel(self, panel: str) -> None:
        """Show or hide one of the three workspace panes while keeping the remaining panes usable."""
        widget_map = {"targets": (self.main_pane, self.target_panel),
                      "graph": (self.right_pane, self.graph_panel),
                      "measurements": (self.right_pane, self.measurement_panel)}
        pane, widget = widget_map[panel]
        visible = self.panel_visibility[panel].get()
        in_pane = str(widget) in pane.panes()
        if visible and not in_pane:
            pane.add(widget, weight={"targets": 1, "graph": 3, "measurements": 1}[panel])
        elif not visible and in_pane:
            pane.forget(widget)

    def _toggle_toolbar(self, section: str) -> None:
        """Show or hide an optional toolbar group such as SSH settings, filters, or file/window actions."""
        widgets = {
            "settings": self.settings_row,
            "ssh": self.ssh_controls,
            "filter": self.filters,
            "files": self.file_controls,
            "windows": self.window_controls,
        }
        widget = widgets[section]
        if self.toolbar_visibility[section].get():
            order = [self.settings_row, self.ssh_controls, self.filters, self.file_controls, self.window_controls]
            index = order.index(widget)
            next_visible = next((candidate for candidate in order[index + 1:]
                                 if candidate.winfo_manager() == "pack"), self.body_pane)
            widget.pack(fill="x", before=next_visible)
        else:
            widget.pack_forget()

    def _toggle_run(self) -> None:
        """Start monitoring when idle or stop the current run when workers are active."""
        if self.running:
            self.stop()
        else:
            self.start()

    def _refresh_run_button(self) -> None:
        """Set the start/stop button label and visual style to match the current run state."""
        if not hasattr(self, "run_button"):
            return
        if self.running:
            self.run_button.configure(text=f"■  {self.tr('Messung stoppen')}", style="Danger.TButton")
        else:
            self.run_button.configure(text=f"▶  {self.tr('Messung starten')}", style="Accent.TButton")

    def open_detached_targets(self) -> None:
        """Open or raise a separate target-entry and status window synchronized with the main target state."""
        window = tk.Toplevel(self.root); window.title("pingee · Ziele"); window.geometry("1040x740"); window.minsize(760, 480)
        ttk.Label(window, text="Ping-Ziele und Status", font=("Segoe UI", 12, "bold"), padding=(10, 8)).pack(anchor="w")
        text = tk.Text(window, height=7, font=("Consolas", 9), wrap="word")
        text.pack(fill="x", padx=10); text.insert("1.0", self.input.get("1.0", "end"))
        controls = ttk.Frame(window, padding=8); controls.pack(fill="x")
        ttk.Button(controls, text="Ziele aus diesem Text hinzufügen",
                   command=lambda: self._add_targets_from_text(text.get("1.0", "end"))).pack(side="left")
        cols = ("hostname", "target", "mac", "status", "last", "last_success", "loss", "last_loss")
        tree = ttk.Treeview(window, columns=cols, show="headings", selectmode="extended")
        self._configure_target_tree(tree)
        yscroll = ttk.Scrollbar(window, orient="vertical", command=tree.yview)
        xscroll = ttk.Scrollbar(window, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.pack(side="top", fill="both", expand=True, padx=(10, 0)); yscroll.pack(side="right", fill="y")
        xscroll.pack(side="bottom", fill="x", padx=10)
        tree.bind("<<TreeviewSelect>>", lambda _e, t=tree: self._detached_target_selection_changed(t))
        ttk.Button(controls, text="Auswahl entfernen", command=lambda: self._remove_targets(set(tree.selection()))).pack(side="right")
        view = {"window": window, "tree": tree, "input": text}
        self.detached_target_views.append(view)
        window.protocol("WM_DELETE_WINDOW", lambda v=view: self._close_detached_target_view(v))
        self._populate_detached_target_tree(tree)
        self._apply_language()

    def _configure_target_tree(self, tree: ttk.Treeview) -> None:
        """Configure sortable target-table columns, headings, widths, and row selection behavior."""
        columns = ("hostname", "target", "mac", "status", "last", "last_success", "loss", "last_loss")
        for column, title, width in [("hostname", "Hostname", 140), ("target", "IP-Adresse / Ziel", 145),
                                     ("mac", "MAC-Adresse", 145), ("status", "Status", 105),
                                     ("last", "Letzter Ping", 100), ("last_success", "Letzter Erfolg", 155),
                                     ("loss", "Verlust", 75), ("last_loss", "Letzter Verlust", 155)]:
            tree.heading(column, text=title, command=lambda c=column, t=tree: self._sort_tree_widget(t, c))
            tree.column(column, width=width, anchor="w" if column in ("hostname", "target", "mac", "last_loss") else "center")
        tree.tag_configure("fail", foreground="#cc4751"); tree.tag_configure("ok", foreground="#169b79")

    def _populate_detached_target_tree(self, tree: ttk.Treeview, targets: set[str] | None = None) -> None:
        """Refresh a detached target table, optionally limiting updates to a supplied set of targets."""
        all_targets = targets is None
        requested = set(self.labels) if all_targets else (targets or set())
        existing = set(tree.get_children()) if all_targets else set()
        for target in requested:
            if target not in self.labels:
                if tree.exists(target): tree.delete(target)
                continue
            values = self._target_tree_values(target)
            tags = ("ok" if self.samples.get(target) and self.samples[target][-1][1] is not None else
                    ("fail" if self.samples.get(target) else ""),)
            if tree.exists(target): tree.item(target, values=values, tags=tags)
            else: tree.insert("", "end", iid=target, values=values, tags=tags)
            if all_targets: existing.discard(target)
        if all_targets:
            for stale in existing: tree.delete(stale)

    def _target_tree_values(self, target: str) -> tuple:
        """Build the display tuple for one target, including hostname, address, MAC, status, latency, success, and loss timestamps."""
        if self.tree.exists(target):
            return self.tree.item(target, "values")
        return (self.labels.get(target, ""), target, self.macs.get(target, ""), "Bereit", "—", "—", "0.0 %", "—")

    def _detached_target_selection_changed(self, tree: ttk.Treeview) -> None:
        """Synchronize selection changes in a detached target table with the application-wide selected-target set."""
        self.selected = set(tree.selection())
        self._redraw_plots()

    def _close_detached_target_view(self, view: dict) -> None:
        """Remove a detached target view from the registry and destroy its window cleanly."""
        if view in self.detached_target_views: self.detached_target_views.remove(view)
        view["window"].destroy()

    def open_detached_measurements(self) -> None:
        """Open or raise a separate live measurement table backed by the same in-memory result stream."""
        window = tk.Toplevel(self.root); window.title("pingee · Messwerte im Arbeitsspeicher")
        window.geometry("980x620"); window.minsize(650, 400)
        ttk.Label(window, text="Messwertverlauf · Live", font=("Segoe UI", 12, "bold"), padding=10).pack(anchor="w")
        cols = ("time", "target", "mac", "latency", "state")
        tree = ttk.Treeview(window, columns=cols, show="headings")
        for column, title, width in [("time", "Zeitstempel", 185), ("target", "Ziel", 170),
                                     ("mac", "MAC-Adresse", 155), ("latency", "Latenz (ms)", 110),
                                     ("state", "Ergebnis", 170)]:
            tree.heading(column, text=title); tree.column(column, width=width, anchor="w")
        yscroll = ttk.Scrollbar(window, orient="vertical", command=tree.yview); tree.configure(yscrollcommand=yscroll.set)
        tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10)); yscroll.pack(side="right", fill="y", pady=(0, 10))
        self.detached_data_trees.append(tree)
        for iid in self.data_tree.get_children():
            tree.insert("", "end", values=self.data_tree.item(iid, "values"))
        window.protocol("WM_DELETE_WINDOW", lambda w=window, t=tree: self._close_detached_measurements(w, t))
        self._apply_language()

    def _close_detached_measurements(self, window: tk.Toplevel, tree: ttk.Treeview) -> None:
        """Release references to a detached measurement table when its window is closed."""
        if tree in self.detached_data_trees: self.detached_data_trees.remove(tree)
        window.destroy()

    def _append_detached_measurement(self, values: tuple) -> None:
        """Append a newly completed measurement row to each open detached measurement table."""
        active = []
        for tree in self.detached_data_trees:
            try:
                if not tree.winfo_exists(): continue
                tree.insert("", 0, values=values)
                children = tree.get_children()
                if len(children) > 2000: tree.delete(*children[2000:])
                active.append(tree)
            except tk.TclError:
                continue
        self.detached_data_trees = active

    def add_from_text(self) -> None:
        """Read the target editor and pass its text to the common target-import routine."""
        self._add_targets_from_text(self.input.get("1.0", "end"))

    def _add_targets_from_text(self, text: str) -> None:
        """Parse, deduplicate, label, and register targets from pasted text, then refresh target views and status."""
        targets = parse_targets(text)
        count = 0
        for address, label, mac in targets:
            if address in self.labels:
                continue
            self.labels[address] = label
            self.macs[address] = mac
            self.last_seen[address] = None
            self.tree.insert("", "end", iid=address, values=(label, address, mac, "Bereit", "—", "—", "0.0 %", "—"))
            count += 1
        self._refresh_target_view()
        self._sync_detached_target_views()
        self.status.set(self.trf("targets_added", count=count, total=len(self.labels)))
        if not targets:
            messagebox.showinfo(self.tr("Keine Ziele erkannt"), self.tr("Bitte gültige IP-Adressen oder Hostnamen einfügen."))

    def import_csv(self) -> None:
        """Open a CSV file, identify target and optional hostname columns, and add its records to the monitor."""
        path = filedialog.askopenfilename(title="Ziel-CSV auswählen", filetypes=[("CSV-Dateien", "*.csv"), ("Alle Dateien", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig", newline="") as f:
                content = f.read()
            found = parse_targets(content)
            count = 0
            for address, label, mac in found:
                if address not in self.labels:
                    self.labels[address] = label
                    self.macs[address] = mac
                    self.last_seen[address] = None
                    self.tree.insert("", "end", iid=address, values=(label, address, mac, "Bereit", "—", "—", "0.0 %", "—")); count += 1
            self._refresh_target_view()
            self._sync_detached_target_views()
            self.status.set(self.trf("csv_imported", count=count))
        except (OSError, UnicodeError) as exc:
            messagebox.showerror(self.tr("CSV-Import fehlgeschlagen"), str(exc))

    def start(self) -> None:
        """Validate settings and targets, create the optional SSH backend, then start one worker per configured target."""
        if not self.labels:
            self.add_from_text()
        if not self.labels:
            return
        try:
            interval = max(0.2, float(self.interval.get())); timeout = max(0.2, float(self.timeout.get()))
            self.concurrency.set(max(1, min(512, int(self.concurrency.get()))))
        except (ValueError, tk.TclError):
            messagebox.showerror(self.tr("Ungültige Einstellung"), self.tr("Intervall und Timeout müssen Zahlen sein.")); return
        new_count = 0
        if not self.running:
            self.run_offline.clear()
            self.run_ever_online.clear()
            self.run_started_at = datetime.now()
            self.first_round_seconds = None
            self.last_seen = {target: None for target in self.labels}
            self.process_gate = threading.BoundedSemaphore(self.concurrency.get())
            self.ssh_remote = None
            if self.use_ssh.get():
                if not self.ssh_host.get().strip() or not self.ssh_username.get().strip() or not self.ssh_password.get():
                    messagebox.showerror(self.tr("SSH-Daten fehlen"), self.tr("Bitte Host, Benutzer und Passwort eingeben.")); return
                self.ssh_remote = SSHRemote(self.ssh_host.get(), self.ssh_username.get(), self.ssh_password.get(), channel_limit=2)
        for target in self.labels:
            if target not in self.workers:
                stop_event = threading.Event()
                worker_gate = None if self.ssh_remote is not None else self.process_gate
                worker = PingWorker(target, self.events, stop_event, interval, timeout, worker_gate, self.ssh_remote)
                self.workers[target] = (stop_event, worker); worker.start(); new_count += 1
            else:
                worker = self.workers[target][1]
                worker.interval = interval
                worker.timeout = timeout
        self.running = True
        self._refresh_run_button()
        self._refresh_target_view()
        capacity = (self.trf("ssh_capacity", pings=self.ssh_remote.BATCH_SIZE * self.ssh_remote.BATCH_WORKERS,
                              channels=self.ssh_remote.BATCH_WORKERS)
                    if self.ssh_remote else self.trf("local_capacity", count=self.concurrency.get()))
        self.status.set(self.trf("measurement_active", count=len(self.labels), capacity=capacity, interval=f"{interval:g}"))

    def stop(self) -> None:
        """Signal every active target worker to stop and arrange safe cleanup of the shared SSH backend."""
        active_workers = [worker for _stop_event, worker in self.workers.values()]
        for stop_event, _worker in self.workers.values():
            stop_event.set()
        self.workers.clear(); self.running = False
        self._refresh_run_button()
        remote = self.ssh_remote
        self.ssh_remote = None
        if remote is not None:
            threading.Thread(target=self._close_ssh_after_workers, args=(active_workers, remote), daemon=True).start()
        self.status.set(self.tr("Messung gestoppt · Messwerte bleiben im Arbeitsspeicher erhalten"))

    def _worker_timing_changed(self, *_args) -> None:
        """Apply edited interval and timeout values to active workers for their subsequent probes."""
        try:
            interval = max(0.2, float(self.interval.get()))
            timeout = max(0.2, float(self.timeout.get()))
        except (ValueError, tk.TclError):
            return
        for _stop_event, worker in self.workers.values():
            worker.interval = interval
            worker.timeout = timeout

    def _schedule_plot_redraw(self) -> None:
        """Coalesce frequent measurement updates into a single delayed graph redraw for GUI responsiveness."""
        if self._plot_redraw_after_id is not None:
            return
        self._plot_redraw_after_id = self.root.after(200, self._run_scheduled_plot_redraw)

    def _run_scheduled_plot_redraw(self) -> None:
        """Clear the pending redraw marker and redraw all active graph canvases."""
        self._plot_redraw_after_id = None
        self._redraw_plots()

    @staticmethod
    def _close_ssh_after_workers(workers: list[PingWorker], remote: SSHRemote) -> None:
        """Join target workers before closing their shared remote connection."""
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=15)
        remote.close()

    def test_ssh(self) -> None:
        """Validate visible SSH fields, disable the test button, and launch a background connection check."""
        host, username, password = self.ssh_host.get().strip(), self.ssh_username.get().strip(), self.ssh_password.get()
        if not host or not username or not password:
            messagebox.showerror(self.tr("SSH-Test fehlgeschlagen"), self.tr("Bitte Host, Benutzer und Passwort eingeben."), parent=self.root)
            return
        if self.ssh_test_button is not None:
            self.ssh_test_button.configure(state="disabled", text=self.tr("Prüfe …"))
        threading.Thread(target=self._test_ssh_background, args=(host, username, password), daemon=True).start()

    def open_dhcp_monitor(self) -> None:
        """Validate SSH configuration and create or raise the independent DHCP packet-monitor window."""
        if self.dhcp_window is not None and self.dhcp_window.winfo_exists():
            self.dhcp_window.deiconify(); self.dhcp_window.lift(); return
        host, username, password = self.ssh_host.get().strip(), self.ssh_username.get().strip(), self.ssh_password.get()
        if not host or not username or not password:
            messagebox.showerror(self.tr("SSH-Daten fehlen"), self.tr("Bitte zuerst Host, Benutzer und Passwort im SSH-Bereich eingeben."), parent=self.root)
            return
        window = tk.Toplevel(self.root)
        window.title("Netzwerkmonitor · DHCP tcpdump")
        window.geometry("1440x820"); window.minsize(1000, 620)
        self.dhcp_window = window

        toolbar = ttk.Frame(window, padding=(12, 10)); toolbar.pack(fill="x")
        self.dhcp_load_button = ttk.Button(toolbar, text="Schnittstellen laden", command=self._load_dhcp_interfaces)
        self.dhcp_load_button.pack(side="left")
        self.dhcp_capture_button = ttk.Button(toolbar, text="Aufzeichnung starten", style="Accent.TButton",
                                              command=self._toggle_dhcp_capture)
        self.dhcp_capture_button.pack(side="left", padx=6)
        ttk.Button(toolbar, text="Pakete als CSV exportieren", command=self._export_dhcp_packets).pack(side="left", padx=6)
        ttk.Label(window, textvariable=self.dhcp_status, anchor="w", padding=(14, 0, 14, 8)).pack(fill="x")

        body = ttk.Panedwindow(window, orient="horizontal"); body.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        filters = ttk.Frame(body, padding=8); body.add(filters, weight=1)
        ttk.Label(filters, text="Interfaces · Live-Filter", style="Section.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(filters, text="Wähle ein oder mehrere Interfaces. Die Aufzeichnung läuft parallel auf any.",
                  wraplength=220, style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        list_frame = ttk.Frame(filters); list_frame.pack(fill="both", expand=True)
        self.dhcp_interface_list = tk.Listbox(list_frame, selectmode="extended", exportselection=False,
                                              font=("Segoe UI", 9), bg="white", fg=self.colors["ink"],
                                              selectbackground="#cfe0ff", selectforeground=self.colors["ink"],
                                              highlightthickness=1, highlightbackground=self.colors["line"],
                                              activestyle="dotbox")
        list_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.dhcp_interface_list.yview)
        self.dhcp_interface_list.configure(yscrollcommand=list_scroll.set)
        self.dhcp_interface_list.pack(side="left", fill="both", expand=True); list_scroll.pack(side="right", fill="y")
        self.dhcp_interface_list.bind("<<ListboxSelect>>", self._dhcp_interface_selection_changed)

        results = ttk.Panedwindow(body, orient="vertical"); body.add(results, weight=4)
        table_frame = ttk.Frame(results, padding=4); results.add(table_frame, weight=4)
        ttk.Label(table_frame, text="DHCP-Pakete", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        columns = ("time", "interface", "direction", "message", "source", "destination", "client_mac", "xid")
        self.dhcp_packet_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        for col, title, width in (("time", "Zeitstempel", 180), ("interface", "Interface", 115),
                                  ("direction", "Richtung", 75), ("message", "DHCP-Nachricht", 130),
                                  ("source", "Quelle", 180), ("destination", "Ziel", 180),
                                  ("client_mac", "Client-MAC", 155), ("xid", "Transaktions-ID", 130)):
            self.dhcp_packet_tree.heading(col, text=title)
            self.dhcp_packet_tree.column(col, width=width, anchor="w")
        self.dhcp_packet_tree.tag_configure("discover", foreground="#2563eb")
        self.dhcp_packet_tree.tag_configure("offer", foreground="#138a69")
        self.dhcp_packet_tree.tag_configure("ack", foreground="#138a69")
        self.dhcp_packet_tree.tag_configure("nak", foreground="#c2414b")
        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.dhcp_packet_tree.yview)
        self.dhcp_packet_tree.configure(yscrollcommand=tree_scroll.set)
        self.dhcp_packet_tree.pack(side="left", fill="both", expand=True); tree_scroll.pack(side="right", fill="y")
        self.dhcp_packet_tree.bind("<<TreeviewSelect>>", self._show_selected_dhcp_packet)

        detail_frame = ttk.Frame(results, padding=4); results.add(detail_frame, weight=2)
        ttk.Label(detail_frame, text="Paketdetails · DHCP-Optionen und tcpdump-Decodierung", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.dhcp_detail_text = tk.Text(detail_frame, height=8, wrap="word", state="disabled",
                                        font=("Cascadia Mono", 9), bg="#fbfcfe", fg=self.colors["ink"],
                                        relief="flat", highlightthickness=1, highlightbackground=self.colors["line"], padx=8, pady=6)
        self.dhcp_detail_text.pack(fill="both", expand=True)

        window.protocol("WM_DELETE_WINDOW", self.close_dhcp_monitor)
        self._render_dhcp_packets()
        self._apply_language()
        self._load_dhcp_interfaces()

    def _load_dhcp_interfaces(self) -> None:
        """Start a background request that discovers remote interfaces and their addresses."""
        if self.dhcp_loading:
            return
        host, username, password = self.ssh_host.get().strip(), self.ssh_username.get().strip(), self.ssh_password.get()
        if not host or not username or not password:
            messagebox.showerror(self.tr("SSH-Daten fehlen"), self.tr("Bitte zuerst Host, Benutzer und Passwort im SSH-Bereich eingeben."), parent=self.dhcp_window)
            return
        self.dhcp_loading = True
        self.dhcp_status.set(self.trf("dhcp_loading", host=host))
        if self.dhcp_load_button is not None: self.dhcp_load_button.configure(state="disabled")
        threading.Thread(target=self._load_dhcp_interfaces_background,
                         args=(host, username, password, self.dhcp_remote), daemon=True).start()

    def _load_dhcp_interfaces_background(self, host: str, username: str, password: str,
                                         remote: SSHRemote | None) -> None:
        """Connect to the remote host, query interface metadata, and enqueue success or error events without touching Tk widgets."""
        created = remote is None
        try:
            if remote is None:
                remote = SSHRemote(host, username, password, channel_limit=2)
            command = "if ! command -v ip >/dev/null 2>&1; then echo 'ip command unavailable' >&2; exit 127; fi; ip -o link show; echo __PPLOT_IP_ADDR__; ip -o addr show"
            rc, output, error = remote.command(command, timeout=12)
            if rc != 0:
                raise RuntimeError(error.strip() or output.strip() or f"Interface-Abfrage endete mit Status {rc}.")
            interfaces = parse_network_interfaces(output)
            if not interfaces:
                raise RuntimeError("Keine Netzwerkschnittstellen erkannt; wird das Linux-System mit iproute2 verwendet?")
            self.events.put(("dhcp_interfaces", interfaces, remote, created))
        except Exception as exc:
            if created and remote is not None:
                remote.close()
            self.events.put(("dhcp_error", f"Schnittstellen konnten nicht geladen werden · {type(exc).__name__}: {exc}"))

    def _apply_dhcp_interfaces(self, interfaces: dict[str, list[str]], remote: SSHRemote) -> None:
        """Store the discovered interfaces, populate the multi-select filter, and retain the SSH connection for capture."""
        self.dhcp_interfaces = interfaces
        self.dhcp_remote = remote
        listing = self.dhcp_interface_list
        if listing is not None and listing.winfo_exists():
            listing.delete(0, "end")
            listing.insert("end", "any — alle Interfaces")
            for name, addresses in sorted(interfaces.items()):
                label = f"{name} — {', '.join(addresses) if addresses else 'keine IP-Adresse'}"
                listing.insert("end", label)
            listing.selection_clear(0, "end"); listing.selection_set(0); listing.activate(0)
        self.dhcp_status.set(self.trf("dhcp_interfaces_loaded", count=len(interfaces)))
        if self.dhcp_capture_button is not None: self.dhcp_capture_button.configure(state="normal")

    def _dhcp_interface_selection_changed(self, _event=None) -> None:
        """Refresh only the visible packet rows after an interface-filter change; capture continues independently."""
        listing = self.dhcp_interface_list
        if listing is None: return
        selected = set(listing.curselection())
        if 0 in selected and len(selected) > 1:
            listing.selection_clear(1, "end")
        elif selected and 0 in selected:
            listing.selection_clear(0)
        self._render_dhcp_packets()

    def _selected_dhcp_interfaces(self) -> set[str] | None:
        """Return the selected interface names, or ``None`` when the view should include every interface."""
        listing = self.dhcp_interface_list
        if listing is None or not listing.curselection() or 0 in listing.curselection():
            return None
        return {listing.get(index).split(" — ", 1)[0] for index in listing.curselection()}

    def _toggle_dhcp_capture(self) -> None:
        """Start tcpdump capture when idle or stop the current DHCP stream when it is running."""
        if self.dhcp_capture is not None and self.dhcp_capture.is_alive():
            self._stop_dhcp_capture()
            return
        if self.dhcp_remote is None:
            self.dhcp_status.set(self.tr("Schnittstellen laden"))
            self._load_dhcp_interfaces()
            return
        stop_event = threading.Event()
        worker = DHCPStreamWorker(self.dhcp_remote, self.events, stop_event)
        self.dhcp_capture_stop, self.dhcp_capture = stop_event, worker
        if self.dhcp_capture_button is not None:
            self.dhcp_capture_button.configure(text="Aufzeichnung stoppen", style="Danger.TButton")
        self.dhcp_status.set(self.trf("dhcp_starting"))
        worker.start()

    def _stop_dhcp_capture(self) -> None:
        """Signal the capture worker to stop and update its controls and status."""
        if self.dhcp_capture_stop is not None:
            self.dhcp_capture_stop.set()
        if self.dhcp_capture is not None and self.dhcp_capture.channel is not None:
            try: self.dhcp_capture.channel.close()
            except Exception: pass
        if self.dhcp_capture_button is not None:
            try:
                if self.dhcp_capture_button.winfo_exists():
                    self.dhcp_capture_button.configure(text="Aufzeichnung starten", style="Accent.TButton")
            except tk.TclError:
                self.dhcp_capture_button = None
        self.dhcp_status.set(self.trf("dhcp_stopped", count=len(self.dhcp_packets)))

    def _render_dhcp_packets(self) -> None:
        """Rebuild the visible DHCP table using the currently selected interfaces and decoded packet records."""
        tree = self.dhcp_packet_tree
        if tree is None or not tree.winfo_exists(): return
        tree.delete(*tree.get_children())
        interfaces = self._selected_dhcp_interfaces()
        for index, packet in reversed(list(enumerate(self.dhcp_packets))):
            if interfaces is not None and packet.get("interface") not in interfaces:
                continue
            message = packet.get("message", "DHCP").upper()
            tag = message.lower() if message.lower() in {"discover", "offer", "ack", "nak"} else ""
            tree.insert("", "end", iid=str(index), values=(packet.get("timestamp", ""), packet.get("interface", ""),
                packet.get("direction", ""), message, packet.get("source", ""), packet.get("destination", ""),
                packet.get("client_mac", ""), packet.get("xid", "")), tags=(tag,) if tag else ())

    def _show_selected_dhcp_packet(self, _event=None) -> None:
        """Display the selected packet’s decoded fields and raw tcpdump output in the detail panel."""
        tree, detail = self.dhcp_packet_tree, self.dhcp_detail_text
        if tree is None or detail is None or not tree.selection(): return
        try: packet = self.dhcp_packets[int(tree.selection()[0])]
        except (IndexError, ValueError): return
        details = (f"{self.tr('Zeitstempel')}: {packet.get('timestamp', '')}\n{self.tr('Interface')}: {packet.get('interface', '')}"
                   f"\n{self.tr('Direction:')} {packet.get('direction', '')}\n{self.tr('Message:')} {packet.get('message', '')}"
                   f"\n{self.tr('Source:')} {packet.get('source', '')}\n{self.tr('Destination:')} {packet.get('destination', '')}"
                   f"\n{self.tr('Client-MAC')}: {packet.get('client_mac', '')}\n{self.tr('Transaktions-ID')}: {packet.get('xid', '')}"
                   f"\n\n{packet.get('details', '')}\n\n{self.tr('Packet decoding:')}\n{packet.get('raw', '')}")
        detail.configure(state="normal"); detail.delete("1.0", "end"); detail.insert("1.0", details); detail.configure(state="disabled")

    def _export_dhcp_packets(self) -> None:
        """Write the captured DHCP packet history to a user-selected CSV file."""
        if not self.dhcp_packets:
            messagebox.showinfo(self.tr("Keine DHCP-Pakete"), self.tr("Es wurden noch keine DHCP-Pakete empfangen."), parent=self.dhcp_window)
            return
        path = filedialog.asksaveasfilename(title="DHCP-Paketverlauf speichern", defaultextension=".csv",
            filetypes=[("CSV-Datei", "*.csv")], initialfile="dhcp-pakete.csv", parent=self.dhcp_window)
        if not path: return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as file:
                writer = csv.writer(file, delimiter=";")
                columns = ("timestamp", "interface", "direction", "message", "source", "destination", "client_mac", "xid", "details", "raw")
                writer.writerow(["Zeitstempel", "Interface", "Richtung", "DHCP-Nachricht", "Quelle", "Ziel", "Client-MAC", "Transaktions-ID", "Optionen / Details", "Rohdaten"])
                for packet in self.dhcp_packets:
                    writer.writerow([packet.get(key, "") for key in columns])
            self.dhcp_status.set(f"{len(self.dhcp_packets)} DHCP-Paket(e) exportiert · {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror(self.tr("Export fehlgeschlagen"), str(exc), parent=self.dhcp_window)

    def close_dhcp_monitor(self) -> None:
        """Stop DHCP capture, close its remote connection, and release child-window references."""
        self._stop_dhcp_capture()
        remote, self.dhcp_remote = self.dhcp_remote, None
        if remote is not None:
            threading.Thread(target=remote.close, daemon=True).start()
        if self.dhcp_window is not None:
            try:
                if self.dhcp_window.winfo_exists():
                    self.dhcp_window.destroy()
            except tk.TclError:
                pass
        self.dhcp_window = None
        self.dhcp_interface_list = self.dhcp_packet_tree = self.dhcp_detail_text = None
        self.dhcp_capture_button = self.dhcp_load_button = None

    def _ssh_credentials_changed(self, *_args) -> None:
        """Enable SSH-dependent actions when the user edits connection credentials."""
        if self._ssh_auto_enable_after_id is not None:
            try: self.root.after_cancel(self._ssh_auto_enable_after_id)
            except tk.TclError: pass
        self._ssh_auto_enable_after_id = self.root.after(250, self._enable_ssh_when_configured)

    def _enable_ssh_when_configured(self) -> None:
        """Update the SSH-dependent controls according to whether all credential fields are populated."""
        self._ssh_auto_enable_after_id = None
        if (self.ssh_host.get().strip() and self.ssh_username.get().strip()
                and self.ssh_password.get()):
            self.use_ssh.set(True)

    def _test_ssh_background(self, host: str, username: str, password: str) -> None:
        """Run the SSH test away from the Tk thread and enqueue a success or failure event."""
        remote = None
        try:
            remote = SSHRemote(host, username, password, channel_limit=1)
            name = remote.test()
            self.events.put(("ssh_test", True, host, name))
        except Exception as exc:
            self.events.put(("ssh_test", False, host, f"{type(exc).__name__}: {exc}"))
        finally:
            if remote is not None:
                remote.close()

    def open_neighbor_monitor(self) -> None:
        """Create or raise the independent ARP/ip-neigh inventory window."""
        if self.neighbor_window is not None and self.neighbor_window.winfo_exists():
            self.neighbor_window.deiconify(); self.neighbor_window.lift(); return
        host, username, password = self.ssh_host.get().strip(), self.ssh_username.get().strip(), self.ssh_password.get()
        if not host or not username or not password:
            messagebox.showerror(self.tr("SSH-Daten fehlen"), self.tr("Bitte zuerst Host, Benutzer und Passwort im SSH-Bereich eingeben."), parent=self.root)
            return
        window = tk.Toplevel(self.root)
        window.title("Netzwerkmonitor · ARP / ip neigh")
        window.geometry("1120x700"); window.minsize(860, 500)
        self.neighbor_window = window
        header = ttk.Frame(window, padding=12); header.pack(fill="x")
        ttk.Label(header, text="Netzwerkgeräte · unabhängig von Ping-Zielen", font=("Segoe UI", 13, "bold")).pack(side="left")
        ttk.Label(header, text="Abfrageintervall (s)").pack(side="left", padx=(20, 5))
        ttk.Spinbox(header, from_=2, to=3600, increment=1, textvariable=self.neighbor_interval, width=6).pack(side="left")
        ttk.Button(header, text="Überwachung starten", command=self.start_neighbor_monitor).pack(side="left", padx=(10, 3))
        ttk.Button(header, text="Stopp", command=self.stop_neighbor_monitor).pack(side="left", padx=3)
        ttk.Button(header, text="Änderungsmarkierungen zurücksetzen", command=self.reset_neighbor_marks).pack(side="right", padx=3)
        ttk.Button(header, text="Verlauf exportieren", command=self.export_neighbor_history).pack(side="right", padx=3)
        ttk.Label(window, textvariable=self.neighbor_monitor_status, anchor="w", padding=(12, 0, 12, 8)).pack(fill="x")

        notebook = ttk.Notebook(window); notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        current_tab = ttk.Frame(notebook, padding=6); notebook.add(current_tab, text="Geräte aktuell")
        columns = ("address", "mac", "interface", "state", "presence", "first_seen", "last_seen", "changes")
        self.neighbor_tree = ttk.Treeview(current_tab, columns=columns, show="headings")
        for column, title, width in [("address", "IP-Adresse", 150), ("mac", "MAC-Adresse", 155),
                                     ("interface", "Interface", 120), ("state", "Nachbarstatus", 110),
                                     ("presence", "Aktuell", 100), ("first_seen", "Erstmals gesehen", 150),
                                     ("last_seen", "Zuletzt gesehen", 150), ("changes", "Änderungen · dauerhaft markiert", 300)]:
            self.neighbor_tree.heading(column, text=title); self.neighbor_tree.column(column, width=width, anchor="w")
        current_scroll = ttk.Scrollbar(current_tab, orient="vertical", command=self.neighbor_tree.yview)
        self.neighbor_tree.configure(yscrollcommand=current_scroll.set)
        self.neighbor_tree.pack(side="left", fill="both", expand=True); current_scroll.pack(side="right", fill="y")
        self.neighbor_tree.tag_configure("new", background="#e9f8ef", foreground="#187449")
        self.neighbor_tree.tag_configure("changed", background="#fff5d9", foreground="#805700")
        self.neighbor_tree.tag_configure("gone", background="#fdebec", foreground="#a8323b")

        history_tab = ttk.Frame(notebook, padding=6); notebook.add(history_tab, text="Beobachtungsverlauf")
        history_cols = ("time", "address", "mac", "interface", "state", "presence", "change")
        self.neighbor_history_tree = ttk.Treeview(history_tab, columns=history_cols, show="headings")
        for column, title, width in [("time", "Zeitpunkt", 175), ("address", "IP-Adresse", 150),
                                     ("mac", "MAC-Adresse", 155), ("interface", "Interface", 120),
                                     ("state", "Nachbarstatus", 110), ("presence", "Sichtbarkeit", 120),
                                     ("change", "Änderung bei diesem Snapshot", 300)]:
            self.neighbor_history_tree.heading(column, text=title); self.neighbor_history_tree.column(column, width=width, anchor="w")
        history_scroll = ttk.Scrollbar(history_tab, orient="vertical", command=self.neighbor_history_tree.yview)
        self.neighbor_history_tree.configure(yscrollcommand=history_scroll.set)
        self.neighbor_history_tree.pack(side="left", fill="both", expand=True); history_scroll.pack(side="right", fill="y")

        changes_tab = ttk.Frame(notebook, padding=6); notebook.add(changes_tab, text="Änderungsereignisse")
        event_filters = ttk.Frame(changes_tab, padding=(4, 2, 4, 8)); event_filters.pack(fill="x")
        ttk.Label(event_filters, text="Änderungen anzeigen:", style="Muted.TLabel").pack(side="left", padx=(0, 8))
        for key, title in (("presence", "Neue / wiederkehrende Geräte"), ("loss", "Verschwundene Geräte"),
                           ("metadata", "MAC / Interface"), ("state", "Neighbor-Statuswechsel")):
            ttk.Checkbutton(event_filters, text=title, variable=self.neighbor_event_filters[key],
                            command=self._refresh_neighbor_tables).pack(side="left", padx=4)
        change_cols = ("time", "address", "change", "details")
        self.neighbor_changes_tree = ttk.Treeview(changes_tab, columns=change_cols, show="headings")
        for column, title, width in [("time", "Zeitpunkt", 175), ("address", "IP-Adresse", 160),
                                     ("change", "Änderung", 180), ("details", "Details", 600)]:
            self.neighbor_changes_tree.heading(column, text=title); self.neighbor_changes_tree.column(column, width=width, anchor="w")
        change_scroll = ttk.Scrollbar(changes_tab, orient="vertical", command=self.neighbor_changes_tree.yview)
        self.neighbor_changes_tree.configure(yscrollcommand=change_scroll.set)
        self.neighbor_changes_tree.pack(side="left", fill="both", expand=True); change_scroll.pack(side="right", fill="y")
        self._refresh_neighbor_tables()
        window.protocol("WM_DELETE_WINDOW", self.close_neighbor_monitor_window)
        self._apply_language()

    def start_neighbor_monitor(self) -> None:
        """Validate settings and start periodic remote neighbor-table snapshots."""
        if (self.neighbor_monitor_thread is not None and self.neighbor_monitor_thread.is_alive()
                and self.neighbor_monitor_stop is not None and not self.neighbor_monitor_stop.is_set()):
            self.neighbor_monitor_status.set(self.trf("neighbor_already_running"))
            return
        host, username, password = self.ssh_host.get().strip(), self.ssh_username.get().strip(), self.ssh_password.get()
        if not host or not username or not password:
            messagebox.showerror(self.tr("SSH-Daten fehlen"), self.tr("Bitte zuerst Host, Benutzer und Passwort im SSH-Bereich eingeben."))
            return
        try:
            interval = max(2.0, float(self.neighbor_interval.get()))
        except (ValueError, tk.TclError):
            messagebox.showerror(self.tr("Ungültiges Intervall"), self.tr("Das Abfrageintervall muss eine Zahl von mindestens 2 Sekunden sein."))
            return
        remote = SSHRemote(host, username, password, channel_limit=1)
        stop_event = threading.Event()
        worker = threading.Thread(target=self._neighbor_poll_loop, args=(remote, stop_event, interval),
                                  name="arp-neighbor-monitor", daemon=True)
        self.neighbor_remote = remote
        self.neighbor_monitor_stop = stop_event
        self.neighbor_monitor_thread = worker
        self.neighbor_monitor_status.set(f"Verbinde mit {host} · erste ARP-/ip-neigh-Abfrage läuft …")
        worker.start()

    def _neighbor_poll_loop(self, remote: SSHRemote, stop_event: threading.Event, interval: float) -> None:
        """Poll ``ip neigh`` (or ``arp -an``) on the configured cadence and enqueue parsed snapshots."""
        command = ("if command -v ip >/dev/null 2>&1; then ip neigh show; "
                   "elif command -v arp >/dev/null 2>&1; then arp -an; "
                   "else echo 'Weder ip noch arp ist installiert' >&2; exit 127; fi")
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                rc, output, error = remote.command(command, timeout=8)
                if rc != 0:
                    raise RuntimeError(error.strip() or output.strip() or f"Remote-Befehl endete mit Status {rc}.")
                now = datetime.now().astimezone()
                self.events.put(("neighbor_snapshot", now, parse_neighbor_table(output), output))
            except Exception as exc:
                self.events.put(("neighbor_error", f"Nachbartabellen-Abfrage fehlgeschlagen · {type(exc).__name__}: {exc}"))
            stop_event.wait(max(0.0, interval - (time.monotonic() - started)))

    def stop_neighbor_monitor(self) -> None:
        """Signal the polling worker to stop and retain collected observations in memory."""
        stop_event = self.neighbor_monitor_stop
        remote = self.neighbor_remote
        self.neighbor_monitor_stop = None
        self.neighbor_remote = None
        if stop_event is not None:
            stop_event.set()
        worker = self.neighbor_monitor_thread
        if remote is not None:
            threading.Thread(target=self._close_neighbor_remote, args=(worker, remote), daemon=True).start()
        self.neighbor_monitor_status.set(self.tr("Überwachung gestoppt · gespeicherte Beobachtungen bleiben erhalten"))

    @staticmethod
    def _close_neighbor_remote(worker: threading.Thread | None, remote: SSHRemote) -> None:
        """Wait briefly for the poller to exit, then close its dedicated SSH connection."""
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=9)
        remote.close()

    def close_neighbor_monitor_window(self) -> None:
        """Stop neighbor polling, destroy the child window, and clear widget references."""
        self.stop_neighbor_monitor()
        if self.neighbor_window is not None:
            self.neighbor_window.destroy()
        self.neighbor_window = None
        self.neighbor_tree = self.neighbor_history_tree = self.neighbor_changes_tree = None

    def _apply_neighbor_snapshot(self, timestamp: datetime, current: dict[str, dict[str, str]], raw: str) -> None:
        """Compare a snapshot with the previous and historical device state, record persistent changes, and append observations."""
        previous = self.neighbor_current
        is_baseline = self.neighbor_snapshot_count == 0
        previous_addresses, current_addresses = set(previous), set(current)
        snapshot_changes: dict[str, list[str]] = defaultdict(list)
        new_events: list[dict] = []

        def record(address: str, kind: str, details: str) -> None:
            """Record a neighbor change once and retain a persistent highlight for its address.

The same event is appended to the full event history and to the current snapshot’s change summary."""
            if kind not in self.neighbor_change_flags[address]:
                self.neighbor_change_flags[address].append(kind)
            event = {"timestamp": timestamp, "address": address, "change": kind, "details": details}
            self.neighbor_changes.append(event); new_events.append(event); snapshot_changes[address].append(kind)

        for address, info in current.items():
            old = self.neighbor_latest.get(address)
            if address not in self.neighbor_first_seen:
                self.neighbor_first_seen[address] = timestamp
                if not is_baseline:
                    record(address, "Neu erkannt", "Gerät ist erstmals seit Beginn der Überwachung aufgetaucht.")
            elif address not in previous_addresses:
                record(address, "Wieder erschienen", "Gerät war in der vorherigen Abfrage nicht vorhanden.")
            if old:
                for key, label in (("mac", "MAC geändert"), ("interface", "Interface geändert"), ("state", "Nachbarstatus geändert")):
                    before, after = old.get(key, ""), info.get(key, "")
                    if before != after:
                        record(address, label, f"{label}: {before or '—'} → {after or '—'}")
            self.neighbor_last_seen[address] = timestamp
            self.neighbor_latest[address] = dict(info)

        for address in sorted(previous_addresses - current_addresses):
            record(address, "Verschwunden", "Gerät fehlt seit dieser Abfrage in der Nachbartabelle.")

        self.neighbor_current = {address: dict(info) for address, info in current.items()}
        self.neighbor_snapshot_count += 1
        self.neighbor_snapshots.append({"timestamp": timestamp, "neighbors": {a: dict(v) for a, v in current.items()}, "raw": raw})
        snapshot_observations = []
        for address, info in current.items():
            observation = {"timestamp": timestamp, "address": address, **info,
                           "presence": "Gesehen", "change": ", ".join(snapshot_changes.get(address, []))}
            self.neighbor_observations.append(observation); snapshot_observations.append(observation)
        for address in sorted(previous_addresses - current_addresses):
            info = dict(self.neighbor_latest.get(address, previous[address]))
            observation = {"timestamp": timestamp, "address": address, **info,
                           "presence": "Verschwunden", "change": "Verschwunden"}
            self.neighbor_observations.append(observation); snapshot_observations.append(observation)
        self.neighbor_monitor_status.set(self.trf(
            "neighbor_snapshot", count=self.neighbor_snapshot_count,
            time=timestamp.strftime('%Y-%m-%d %H:%M:%S'), devices=len(current),
            marked=len(self.neighbor_change_flags), observations=len(self.neighbor_observations)))
        self._refresh_neighbor_tables(new_events, snapshot_observations)

    def _refresh_neighbor_tables(self, new_events: list[dict] | None = None,
                                 new_observations: list[dict] | None = None) -> None:
        """Refresh current-device, observation-history, and change-event tables from in-memory records."""
        tree = self.neighbor_tree
        if tree is not None and tree.winfo_exists():
            present = set(self.neighbor_current)
            for address, info in self.neighbor_latest.items():
                is_present = address in present
                flags = self.neighbor_change_flags.get(address, [])
                first_seen = self.neighbor_first_seen.get(address)
                last_seen = self.neighbor_last_seen.get(address)
                tag = "gone" if (not is_present and "Verschwunden" in flags) else (
                    "new" if flags == ["Neu erkannt"] else ("changed" if flags else ""))
                values = (address, info.get("mac", ""), info.get("interface", ""), info.get("state", ""),
                          "Gesehen" if is_present else "Verschwunden",
                          first_seen.strftime("%Y-%m-%d %H:%M:%S") if first_seen else "—",
                          last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen else "—",
                          ", ".join(flags) if flags else "—")
                if tree.exists(address): tree.item(address, values=values, tags=(tag,) if tag else ())
                else: tree.insert("", "end", iid=address, values=values, tags=(tag,) if tag else ())
        history = self.neighbor_history_tree
        if history is not None and history.winfo_exists():
            if new_observations is None:
                history.delete(*history.get_children())
                observation_items = list(self.neighbor_observations)[-1000:]
            else:
                observation_items = new_observations
            for item in reversed(observation_items):
                history.insert("", 0, values=(item["timestamp"].strftime("%Y-%m-%d %H:%M:%S"), item["address"],
                                               item.get("mac", ""), item.get("interface", ""), item.get("state", ""),
                                               item["presence"], item.get("change", "")))
            if len(history.get_children()) > 2000:
                history.delete(*history.get_children()[2000:])
        changes = self.neighbor_changes_tree
        if changes is not None and changes.winfo_exists():
            if new_events is None:
                changes.delete(*changes.get_children())
                event_items = [event for event in list(self.neighbor_changes)[-1000:]
                               if self._neighbor_event_is_visible(event)]
            else:
                event_items = [event for event in new_events if self._neighbor_event_is_visible(event)]
            for event in reversed(event_items):
                changes.insert("", 0, values=(event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"), event["address"],
                                               event["change"], event["details"]))
            if len(changes.get_children()) > 2000:
                changes.delete(*changes.get_children()[2000:])

    def _neighbor_event_is_visible(self, event: dict) -> bool:
        """Apply the change-category filters to a neighbor event without changing the stored history."""
        kind = event.get("change", "")
        if kind in {"Neu erkannt", "Wieder erschienen"}:
            return self.neighbor_event_filters["presence"].get()
        if kind == "Verschwunden":
            return self.neighbor_event_filters["loss"].get()
        if kind == "Nachbarstatus geändert":
            return self.neighbor_event_filters["state"].get()
        if kind in {"MAC geändert", "Interface geändert"}:
            return self.neighbor_event_filters["metadata"].get()
        return True

    def reset_neighbor_marks(self) -> None:
        """Clear persistent change highlights while preserving snapshots and event history."""
        self.neighbor_change_flags.clear()
        self._refresh_neighbor_tables()
        self.neighbor_monitor_status.set(self.tr("Änderungsmarkierungen zurückgesetzt · Beobachtungs- und Ereignisverlauf bleibt erhalten"))

    def export_neighbor_history(self) -> None:
        """Export neighbor snapshots, observations, and change events to CSV."""
        if not self.neighbor_observations:
            messagebox.showinfo(self.tr("Keine Beobachtungen"), self.tr("Es wurden noch keine ARP-/ip-neigh-Beobachtungen gespeichert."))
            return
        path = filedialog.asksaveasfilename(title="ARP-/ip-neigh-Verlauf speichern", defaultextension=".csv",
                                           filetypes=[("CSV-Datei", "*.csv")], initialfile="nachbartabellen-verlauf.csv")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as file:
                writer = csv.writer(file, delimiter=";")
                writer.writerow(["Zeitpunkt", "IP-Adresse", "MAC-Adresse", "Interface", "Nachbarstatus", "Sichtbarkeit", "Änderung in diesem Snapshot", "Dauerhafte Markierungen"])
                for item in self.neighbor_observations:
                    writer.writerow([item["timestamp"].isoformat(timespec="seconds"), item["address"], item.get("mac", ""),
                                     item.get("interface", ""), item.get("state", ""), item["presence"], item.get("change", ""),
                                     ", ".join(self.neighbor_change_flags.get(item["address"], []))])
            self.neighbor_monitor_status.set(f"Nachbartabellen-Verlauf exportiert · {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror(self.tr("Export fehlgeschlagen"), str(exc))

    def remove_selected(self) -> None:
        """Remove the currently selected targets from the main target table."""
        targets_to_remove = set(self.tree.selection())
        if self.large_mode:
            targets_to_remove.update(target for target, var in self.card_vars.items() if var.get())
        else:
            targets_to_remove.update(self.selected)
        self._remove_targets(targets_to_remove)

    def _remove_targets(self, targets_to_remove: set[str]) -> None:
        """Stop and remove selected target workers and delete their target-specific state and table rows."""
        for target in targets_to_remove:
            if target in self.workers:
                self.workers[target][0].set(); del self.workers[target]
            self.labels.pop(target, None); self.samples.pop(target, None)
            self.macs.pop(target, None)
            self.card_widgets.pop(target, None)
            self.last_seen.pop(target, None); self.run_offline.discard(target); self.run_ever_online.discard(target); self.card_vars.pop(target, None)
            if self.tree.exists(target):
                self.tree.delete(target)
            for child in self.card_frame.winfo_children():
                if getattr(child, "target_id", None) == target:
                    child.destroy()
        self.selected.difference_update(targets_to_remove)
        self._refresh_target_view()
        self._sync_detached_target_views()
        self._redraw_plots()

    def _sync_detached_target_views(self, targets: set[str] | None = None) -> None:
        """Propagate target additions, removals, and status changes to open detached views."""
        active = []
        for view in self.detached_target_views:
            try:
                if not view["window"].winfo_exists(): continue
                self._populate_detached_target_tree(view["tree"], targets)
                active.append(view)
            except tk.TclError:
                continue
        self.detached_target_views = active

    def _selection_changed(self, _event=None) -> None:
        """Update the shared target selection when the main target list selection changes."""
        selection = set(self.tree.selection())
        if selection:
            self.selected = selection
        self._redraw_plots()

    def _drain_events(self) -> None:
        """Consume worker events on Tk’s main thread and update histories, controls, tables, dialogs, and graph redraw scheduling."""
        changed = False
        changed_targets: set[str] = set()
        while True:
            try: event = self.events.get_nowait()
            except queue.Empty: break
            if event[0] == "neighbor_snapshot":
                self._apply_neighbor_snapshot(event[1], event[2], event[3])
                continue
            if event[0] == "neighbor_error":
                self.neighbor_monitor_status.set(event[1])
                continue
            if event[0] == "dhcp_interfaces":
                self.dhcp_loading = False
                if self.dhcp_load_button is not None:
                    self.dhcp_load_button.configure(state="normal")
                self._apply_dhcp_interfaces(event[1], event[2])
                continue
            if event[0] == "dhcp_packet":
                self.dhcp_packets.append(event[1])
                self._render_dhcp_packets()
                continue
            if event[0] == "dhcp_status":
                self.dhcp_status.set(self.trf("dhcp_running") if event[1] == "__RUNNING__" else event[1])
                continue
            if event[0] == "dhcp_error":
                self.dhcp_status.set(event[1])
                self.dhcp_loading = False
                if self.dhcp_load_button is not None:
                    self.dhcp_load_button.configure(state="normal")
                if self.dhcp_capture_button is not None:
                    self.dhcp_capture_button.configure(text="Aufzeichnung starten", style="Accent.TButton")
                continue
            if event[0] == "ssh_test":
                message = self.trf("ssh_success", host=event[2], hostname=event[3]) if event[1] else self.trf("ssh_failed", host=event[2], error=event[3])
                self.status.set(message)
                if self.ssh_test_button is not None:
                    self.ssh_test_button.configure(state="normal", text=self.tr("SSH testen"))
                if event[1]:
                    messagebox.showinfo(self.tr("SSH-Verbindung erfolgreich"), message, parent=self.root)
                else:
                    messagebox.showerror(self.tr("SSH-Verbindung fehlgeschlagen"), message, parent=self.root)
                continue
            _kind, target, timestamp, latency, result, mac = event
            if target not in self.labels: continue
            if mac:
                self.macs[target] = mac
            self.samples[target].append((timestamp, latency, result)); changed = True
            changed_targets.add(target)
            if latency is None:
                self.last_loss[target] = timestamp
                if target not in self.run_ever_online:
                    self.run_offline.add(target)
            else:
                self.run_ever_online.add(target)
                self.last_seen[target] = timestamp
                self.run_offline.discard(target)
            values = self.samples[target]
            total = len(values); lost = sum(1 for _, ms, _ in values if ms is None)
            loss = lost * 100 / total if total else 0
            last = f"{latency:.2f} ms" if latency is not None else "Timeout"
            if self.tree.exists(target):
                loss_at = self.last_loss.get(target)
                loss_text = loss_at.strftime("%Y-%m-%d %H:%M:%S") if loss_at else "—"
                success_at = self.last_seen.get(target)
                success_text = success_at.strftime("%Y-%m-%d %H:%M:%S") if success_at else "—"
                self.tree.item(target, values=(self.labels.get(target, ""), target, self.macs.get(target, ""), result, last, success_text, f"{loss:.1f} %", loss_text), tags=("ok" if latency is not None else "fail",))
            if self.large_mode:
                self._update_card(target)
            self.data_tree.insert("", 0, values=(timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], target, self.macs.get(target, ""), f"{latency:.3f}" if latency is not None else "", result))
            self._append_detached_measurement(self.data_tree.item(self.data_tree.get_children("")[0], "values"))
            # Keep the UI bounded while retaining the full measurement series in RAM.
            if len(self.data_tree.get_children()) > 2000:
                self.data_tree.delete(*self.data_tree.get_children()[2000:])
        if changed:
            self._sync_detached_target_views(changed_targets)
            if self.hide_run_offline.get() or self.hide_current_offline.get():
                self._refresh_target_view()
            self._schedule_plot_redraw()
            if self.running:
                checked = sum(1 for target in self.labels if self.samples.get(target))
                if checked == len(self.labels) and self.first_round_seconds is None and self.run_started_at is not None:
                    self.first_round_seconds = max(0.0, (datetime.now() - self.run_started_at).total_seconds())
                online = sum(bool(self.samples.get(t)) and self.samples[t][-1][1] is not None for t in self.labels)
                offline = sum(bool(self.samples.get(t)) and self.samples[t][-1][1] is None for t in self.labels)
                mac_count = sum(bool(self.macs.get(t)) for t in self.labels)
                if self.ssh_remote:
                    source = self.trf("ssh_capacity", pings=self.ssh_remote.BATCH_SIZE * self.ssh_remote.BATCH_WORKERS,
                                      channels=self.ssh_remote.BATCH_WORKERS)
                else:
                    source = self.trf("local_capacity", count=self.concurrency.get())
                prefix = (self.trf("first_round_progress", done=checked, total=len(self.labels)) if checked < len(self.labels)
                          else self.trf("first_round_duration", seconds=self.first_round_seconds))
                self.status.set(self.trf("health_summary", online=online, offline=offline,
                    unchecked=len(self.labels)-checked, macs=mac_count, total=len(self.labels), source=source))
                self.status.set(prefix + self.status.get())
        if self.root.winfo_exists():
            self._drain_after_id = self.root.after(50, self._drain_events)

    def _draw_plot(self, canvas: tk.Canvas) -> None:
        """Render selected target latency series and packet-loss markers into one graph canvas."""
        if not canvas.winfo_exists(): return
        canvas.delete("all")
        if canvas is self.plot_tooltip_canvas:
            self.plot_tooltip_canvas = None
            self.plot_tooltip_window_id = None
            self._hide_plot_tooltip()
        w, h = canvas.winfo_width(), canvas.winfo_height()
        if w < 80 or h < 80: return
        left, right, top, bottom = 58, 18, 18, 35
        pw, ph = w-left-right, h-top-bottom
        targets = [t for t in (self.selected if self.selected else set(self.labels)) if t in self.samples]
        points = [(t, list(self.samples[t])) for t in targets if self.samples[t]]
        start_at, end_at = self._selected_time_range()
        points = [(target, [(ts, ms, result) for ts, ms, result in data if (start_at is None or ts >= start_at) and (end_at is None or ts <= end_at)]) for target, data in points]
        points = [(target, data) for target, data in points if data]
        valid = [ms for _, data in points for _, ms, _ in data if ms is not None]
        ymax = max(50.0, max(valid, default=0) * 1.2)
        for i in range(5):
            y = top + ph*i/4
            canvas.create_line(left, y, w-right, y, fill="#e8edf4")
            canvas.create_text(left-8, y, text=f"{ymax*(4-i)/4:.0f}", anchor="e", fill="#8793a5", font=("Segoe UI", 8))
        canvas.create_text(15, top+ph/2, text="ms", fill="#8793a5", font=("Segoe UI", 8))
        canvas.create_line(left, top, left, top+ph, fill="#cdd5e0")
        canvas.create_line(left, top+ph, w-right, top+ph, fill="#cdd5e0")
        if start_at is not None and end_at is not None:
            for i in range(5):
                ts = start_at + (end_at-start_at)*i/4
                x = left + pw*i/4
                canvas.create_text(x, top+ph+15, text=ts.strftime("%H:%M:%S"), fill="#8793a5", font=("Segoe UI", 8))
        else:
            for i in range(5):
                canvas.create_text(left+pw*i/4, top+ph+15, text=f"{i*25}%", fill="#8793a5", font=("Segoe UI", 8))
        palette = ["#367bf5", "#1da987", "#ed923a", "#aa6ee8", "#e35f72", "#1ea2b6", "#7c8d34", "#e05cb1"]
        point_registry = []
        for idx, (target, data) in enumerate(points):
            color = palette[idx % len(palette)]; n = len(data)
            stride = max(1, n // max(1, int(pw)))
            segment = []
            sampled_indices = set(range(0, n, stride))
            sampled_indices.update(j for j, sample in enumerate(data) if sample[1] is None)
            for j in sorted(sampled_indices):
                ts, ms, res = data[j]
                if start_at is not None and end_at is not None and end_at > start_at:
                    x = left + max(0.0, min(1.0, (ts-start_at).total_seconds()/(end_at-start_at).total_seconds())) * pw
                else:
                    x = left + (j / max(1, n-1)) * pw
                if ms is None:
                    if len(segment) > 2: canvas.create_line(*segment, fill=color, width=2)
                    segment = []
                    y = top + ph - 5
                    canvas.create_polygon(x, y-6, x-6, y+5, x+6, y+5, fill="#dc4451", outline="white", width=1)
                    point_registry.append((x, y, target, ts, None, res))
                    continue
                y = top + ph * (1 - min(ms, ymax) / ymax)
                segment.extend((x, y))
                canvas.create_oval(x-3, y-3, x+3, y+3, fill=color, outline="white", width=1)
                point_registry.append((x, y, target, ts, ms, res))
            if len(segment) > 2: canvas.create_line(*segment, fill=color, width=2, smooth=False)
        self.plot_points[canvas] = point_registry
        if not points:
            canvas.create_text(w/2, h/2, text=self.tr("Messung starten, um Latenzwerte zu sehen"), fill="#98a4b5", font=("Segoe UI", 10))
        canvas.create_text(left+pw/2, h-7, text=self.tr("Uhrzeit"), fill="#8793a5", font=("Segoe UI", 8))
        # Small legend.
        x, y = left+8, 12
        for idx, (target, _data) in enumerate(points[:8]):
            color = palette[idx % len(palette)]
            canvas.create_line(x, y, x+14, y, fill=color, width=3)
            short = target if len(target) < 20 else target[:17]+"…"
            canvas.create_text(x+19, y, text=short, anchor="w", fill="#536176", font=("Segoe UI", 8))
            x += 120

    def _target_is_currently_offline(self, target: str) -> bool:
        """Return whether the target’s newest recorded probe failed."""
        return bool(self.samples.get(target)) and self.samples[target][-1][1] is None

    def _refresh_target_view(self) -> None:
        """Rebuild the main target display, applying text, selection, and offline filters or compact cards for large inventories."""
        targets = list(self.labels)
        self.large_mode = len(targets) >= self.large_threshold
        search = self.filter_text.get().strip().casefold()
        visible = []
        for target in targets:
            label = self.labels.get(target, "")
            if search and search not in target.casefold() and search not in label.casefold():
                continue
            if self.hide_run_offline.get() and target in self.run_offline:
                continue
            if self.hide_current_offline.get() and self._target_is_currently_offline(target):
                continue
            visible.append(target)
        if self.large_mode:
            self.tree.pack_forget()
            self.cards.pack(fill="both", expand=True, pady=(0, 8))
            visible_set = set(visible)
            for target, widgets in list(self.card_widgets.items()):
                if target not in visible_set:
                    widgets["card"].destroy()
                    self.card_widgets.pop(target, None)
            for target in visible:
                if target in self.card_widgets:
                    widgets = self.card_widgets[target]
                    widgets["name"].configure(text=self.labels.get(target) or "(kein Hostname)")
                    widgets["mac"].configure(text=self.macs.get(target) or "MAC unbekannt")
                    self._update_card(target)
                    continue
                var = self.card_vars.setdefault(target, tk.BooleanVar(value=(not self.selected or target in self.selected)))
                card = tk.Frame(self.card_frame, bg="#f0fdf8", highlightthickness=1, highlightbackground="#b8e8d6", padx=8, pady=5)
                card.target_id = target
                card.pack(fill="x", pady=2, padx=2)
                tk.Checkbutton(card, variable=var, command=lambda t=target: self._card_selection_changed(t), bg=card["bg"], activebackground=card["bg"], bd=0).pack(side="left")
                name = self.labels.get(target) or "(kein Hostname)"
                name_widget = tk.Label(card, text=name, bg=card["bg"], fg="#1a334a", font=("Segoe UI", 9, "bold"), anchor="w")
                name_widget.pack(side="left", fill="x", expand=True)
                address_widget = tk.Label(card, text=target, bg=card["bg"], fg="#64758a", font=("Consolas", 8))
                address_widget.pack(side="left", padx=8)
                mac_widget = tk.Label(card, text=self.macs.get(target) or "MAC unbekannt", bg=card["bg"], fg="#8793a5", font=("Consolas", 8))
                mac_widget.pack(side="left", padx=8)
                state_widget = tk.Label(card, text="Bereit", bg=card["bg"], fg="#64758a", font=("Segoe UI", 8), width=23, anchor="e")
                state_widget.pack(side="right")
                self.card_widgets[target] = {"card": card, "name": name_widget, "address": address_widget, "mac": mac_widget, "state": state_widget}
                self._update_card(target)
        else:
            self.cards.pack_forget()
            self.tree.pack(fill="both", expand=True, pady=(0, 8))
            visible_set = set(visible)
            for target in targets:
                if self.tree.exists(target):
                    if target in visible_set:
                        if target not in self.tree.get_children(""):
                            self.tree.move(target, "", "end")
                    else:
                        self.tree.detach(target)
            self.selected &= set(targets)

    def _update_card(self, target: str) -> None:
        """Refresh one compact target status card with its address, name, latest result, and selection state."""
        widgets = self.card_widgets.get(target)
        if widgets:
            card = widgets["card"]
            samples = self.samples.get(target, ())
            live = samples[-1] if samples else None
            online = bool(live and live[1] is not None)
            bg = "#effbf6" if online else ("#fff8e7" if live is None else "#fff0f0")
            border = "#9bdfc4" if online else ("#f2d58d" if live is None else "#f0aaaa")
            for key in ("name", "address", "mac", "state"):
                widgets[key].configure(bg=bg)
            card.configure(bg=bg, highlightbackground=border)
            if live:
                when = live[0].strftime("%H:%M:%S")
                text = f"{live[1]:.2f} ms · {when}" if online else f"Offline · {when}"
            else:
                text = "Bereit"
            widgets["state"].configure(text=text, fg="#16866b" if online else ("#bd8514" if live is None else "#c7444c"))

    def _card_selection_changed(self, target: str) -> None:
        """Synchronize a compact target card’s selected state with the shared target selection."""
        selected = {t for t, var in self.card_vars.items() if var.get()}
        self.selected = selected
        self._redraw_plots()

    def select_all(self) -> None:
        """Select every currently configured target and refresh dependent graph selection."""
        self.selected = set(self.labels)
        for target, var in self.card_vars.items():
            var.set(True)
        self.tree.selection_set(tuple(t for t in self.tree.get_children("") if t in self.selected))
        self._redraw_plots()

    def clear_selection(self) -> None:
        """Clear the current target selection and refresh dependent graph selection."""
        self.selected.clear()
        for var in self.card_vars.values():
            var.set(False)
        self.tree.selection_remove(self.tree.selection())
        self._redraw_plots()

    def _sort_targets(self, column: str) -> None:
        """Sort the main target list by the column whose heading was clicked."""
        self._sort_tree_widget(self.tree, column)
        self._sync_detached_target_views()

    def _sort_tree_widget(self, tree: ttk.Treeview, column: str) -> None:
        """Sort a Treeview column while preserving numeric and timestamp ordering where applicable."""
        items = list(tree.get_children(""))
        reverse = self.sort_reverse.get(column, False)
        column_index = tree["columns"].index(column)
        def key(iid: str):
            """Build a sortable key for a target-table row.

Numeric latency, loss, and address fields sort by value; empty values are placed consistently with other missing data."""
            value = tree.item(iid, "values")[column_index]
            if column == "loss":
                try: return float(str(value).replace("%", "").replace(",", ".").strip())
                except ValueError: return -1.0
            if column in {"last_loss", "last_success"}:
                try: return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                except ValueError: return datetime.min
            return str(value).casefold()
        for index, iid in enumerate(sorted(items, key=key, reverse=reverse)):
            tree.move(iid, "", index)
        self.sort_reverse[column] = not reverse

    def _selected_time_range(self) -> tuple[datetime | None, datetime | None]:
        """Resolve the graph’s current preset, relative-duration, or explicit start/end time window."""
        mode = self._locale_source(self.window_mode.get())
        now = datetime.now().astimezone()
        durations = {"Letzte 30 Sekunden": 30, "Letzte 5 Minuten": 300, "Letzte 15 Minuten": 900,
                     "Letzte Stunde": 3600, "Letzte 6 Stunden": 21600}
        if mode in durations:
            return now-timedelta(seconds=durations[mode]), now
        if mode == "Eigene relative Dauer":
            try:
                amount = float(self.relative_amount.get().strip().replace(",", "."))
                if amount <= 0: raise ValueError("Dauer muss größer als 0 sein.")
                factor = {"Sekunden": 1, "Minuten": 60, "Stunden": 3600}[self._locale_source(self.relative_unit.get())]
                return now-timedelta(seconds=amount*factor), now
            except (ValueError, OverflowError) as exc:
                self.status.set(f"{self.tr('Relative Dauer ungültig')}: {exc}")
                return now-timedelta(minutes=5), now
        if mode == "Benutzerdefiniert":
            try:
                start = datetime.strptime(self.custom_from.get().strip(), "%Y-%m-%d %H:%M:%S").astimezone()
                end = datetime.strptime(self.custom_to.get().strip(), "%Y-%m-%d %H:%M:%S").astimezone()
                if end <= start: raise ValueError("Bis muss nach Von liegen.")
                return start, end
            except ValueError as exc:
                if self.custom_from.get().strip() or self.custom_to.get().strip():
                    self.status.set(f"{self.tr('Zeitfenster ungültig')}: {exc}")
                return now-timedelta(minutes=5), now
        timestamps = [sample[0] for target in self.labels for sample in self.samples.get(target, ())]
        if not timestamps:
            return None, None
        start, end = min(timestamps), max(timestamps)
        return (start, end) if end > start else (start-timedelta(seconds=1), end+timedelta(seconds=1))

    def _apply_relative_window(self) -> None:
        """Validate the custom duration and update the selected graph time-range preset."""
        self.window_mode.set(self.tr("Eigene relative Dauer"))
        self._redraw_plots()

    def _redraw_plots(self) -> None:
        """Redraw every open graph canvas using current selections and time-window controls."""
        for canvas in list(self.plot_canvases):
            try:
                if canvas.winfo_exists(): self._draw_plot(canvas)
                else: self.plot_canvases.remove(canvas)
            except tk.TclError:
                if canvas in self.plot_canvases: self.plot_canvases.remove(canvas)

    def open_plot_window(self) -> None:
        """Open or raise a maximized graph window that shares the live measurement data and hover behavior."""
        if self.plot_window is not None and self.plot_window.winfo_exists():
            self.plot_window.deiconify(); self.plot_window.lift(); return
        window = tk.Toplevel(self.root); window.title("pingee · Latenzverlauf")
        window.geometry("1400x850"); window.minsize(900, 600)
        try: window.state("zoomed")
        except tk.TclError: pass
        self.plot_window = window
        ttk.Label(window, textvariable=self.plot_detail, anchor="w", padding=8).pack(fill="x", side="bottom")
        canvas = tk.Canvas(window, bg="#fbfcfe", highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.plot_canvases.append(canvas)
        canvas.bind("<Configure>", lambda _e: self._redraw_plots())
        canvas.bind("<Motion>", self._plot_mousemove)
        canvas.bind("<Leave>", lambda _e: self._hide_plot_tooltip())
        window.protocol("WM_DELETE_WINDOW", lambda: self._close_plot_window(window, canvas))
        self._apply_language()
        self._redraw_plots()

    def _close_plot_window(self, window: tk.Toplevel, canvas: tk.Canvas) -> None:
        """Hide any tooltip, unregister the canvas, and destroy its graph window."""
        if self.plot_tooltip_canvas is canvas:
            self._hide_plot_tooltip()
        if canvas in self.plot_canvases: self.plot_canvases.remove(canvas)
        self.plot_window = None
        window.destroy()

    def _plot_mousemove(self, event) -> None:
        """Find the nearest graph point to the pointer and show its timestamp, target, MAC, latency, and result."""
        candidates = [p for p in self.plot_points.get(event.widget, ()) if abs(p[0]-event.x) <= 8 and abs(p[1]-event.y) <= 8]
        if not candidates:
            self.plot_detail.set(self.tr("Bewege den Mauszeiger über einen Messpunkt für Details."))
            self._hide_plot_tooltip()
            return
        x, y, target, timestamp, latency, result = min(candidates, key=lambda p: (p[0]-event.x)**2+(p[1]-event.y)**2)
        host = self.labels.get(target, "")
        mac = self.macs.get(target, "")
        latency_text = f"{latency:.3f} ms" if latency is not None else self.tr("Paketverlust / Timeout")
        detail = (f"{self.tr('Zeit:')} {timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
                  f"{self.tr('Hostname:')} {host or '—'}\n{self.tr('Ziel')}: {target}\n{self.tr('MAC-Adresse')}: {mac or '—'}\n"
                  f"{self.tr('Latenz:')} {latency_text}\n{self.tr('Ergebnis:')} {result}")
        self.plot_detail.set(detail.replace("\n", " · "))
        self._show_plot_tooltip(event.widget, x, y, detail, latency is not None)

    def _show_plot_tooltip(self, canvas: tk.Canvas, x: float, y: float, detail: str, success: bool) -> None:
        """Position and style the graph detail popup near a point while keeping it inside the canvas bounds."""
        try:
            if (self.plot_tooltip is None or not self.plot_tooltip.winfo_exists()
                    or self.plot_tooltip_canvas not in (None, canvas)):
                if self.plot_tooltip is not None:
                    try: self.plot_tooltip.destroy()
                    except tk.TclError: pass
                tooltip = tk.Frame(canvas, bg="#15243a", padx=9, pady=7,
                                   highlightthickness=1, highlightbackground="#ffffff")
                label = tk.Label(tooltip, textvariable=self.plot_detail, justify="left", anchor="w",
                                 bg="#15243a", fg="white", font=("Segoe UI", 9),
                                 padx=2, pady=1)
                label.pack()
                self.plot_tooltip = tooltip
            self.plot_tooltip_canvas = canvas
            self.plot_tooltip.update_idletasks()
            width = self.plot_tooltip.winfo_reqwidth()
            height = self.plot_tooltip.winfo_reqheight()
            tooltip_x = min(max(4, int(x + 14)), max(4, canvas.winfo_width() - width - 4))
            tooltip_y = int(y - height - 14)
            if tooltip_y < 4:
                tooltip_y = min(canvas.winfo_height() - height - 4, int(y + 14))
            tooltip_y = max(4, tooltip_y)
            if self.plot_tooltip_window_id is None:
                self.plot_tooltip_window_id = canvas.create_window(
                    tooltip_x, tooltip_y, window=self.plot_tooltip, anchor="nw")
            else:
                canvas.coords(self.plot_tooltip_window_id, tooltip_x, tooltip_y)
                canvas.itemconfigure(self.plot_tooltip_window_id, state="normal")
        except tk.TclError:
            self._hide_plot_tooltip()

    def _hide_plot_tooltip(self) -> None:
        """Hide the transient point-detail popup without changing the selected graph data."""
        canvas = self.plot_tooltip_canvas
        window_id = self.plot_tooltip_window_id
        self.plot_tooltip_canvas = None
        self.plot_tooltip_window_id = None
        if canvas is not None and window_id is not None:
            try: canvas.itemconfigure(window_id, state="hidden")
            except tk.TclError: pass

    def export_data(self) -> None:
        """Export all in-memory ping measurements to a user-selected CSV file."""
        if not any(self.samples.values()):
            messagebox.showinfo(self.tr("Keine Messwerte"), self.tr("Es gibt noch keine Messwerte zum Speichern.")); return
        path = filedialog.asksaveasfilename(title=self.tr("Messwerte speichern"), defaultextension=".csv", filetypes=[("CSV-Datei", "*.csv")], initialfile="pingee-measurements.csv")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["Zeitstempel", "Hostname", "Ziel", "MAC-Adresse", "Latenz_ms", "Ergebnis"])
                for target, data in self.samples.items():
                    for timestamp, latency, result in data:
                        writer.writerow([timestamp.isoformat(timespec="milliseconds"), self.labels.get(target, ""), target, self.macs.get(target, ""), "" if latency is None else f"{latency:.3f}", result])
            self.status.set(f"Messwerte gespeichert · {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror(self.tr("Speichern fehlgeschlagen"), str(exc))

    def _close(self) -> None:
        """Stop background activity, close remote resources, and destroy the root window."""
        self.close_dhcp_monitor()
        self.stop_neighbor_monitor()
        self.stop()
        for callback_id in (self._drain_after_id, self._plot_redraw_after_id):
            if callback_id is not None:
                try: self.root.after_cancel(callback_id)
                except tk.TclError: pass
        self.root.destroy()


def main() -> None:
    """Create the Tk root, instantiate the application, and run the desktop event loop."""
    root = tk.Tk()
    PingeeApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
