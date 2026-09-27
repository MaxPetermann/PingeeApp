# pingee

**pingee** is a desktop network monitor for continuous ICMP latency and availability measurements across many targets. It also provides optional remote ping execution over SSH, neighbor-table change tracking, and DHCP packet capture through `tcpdump`.

The application is designed for desktop use with a mouse and keyboard. Its graphical interface is built with Python's standard-library Tkinter. English is the default UI language; German, Spanish, Dutch, Polish, and Simplified Chinese are also available.

## Features

- Monitor many IP addresses and hostnames concurrently, with a configurable interval, timeout, and local process limit.
- See live latency and packet-loss data in sortable target tables and time-based graphs.
- Paste plain address lists, Markdown or tabular device inventories, and supported network-topology exports. Hostnames are retained when they can be associated with an address.
- Import targets from CSV and export measurements, DHCP packets, and neighbor histories to CSV.
- Run probes on a remote Linux host over SSH. A small pool of persistent shell channels carries many asynchronous ping requests.
- Resolve target MAC addresses from the remote host's neighbor table when available.
- Independently poll `ip neigh` (or `arp -an`) to record newly seen, returning, changed, and disappeared devices.
- Capture DHCPv4/v6 packets with remote `tcpdump`, automatically list available interfaces and addresses, and filter the live view across one or more interfaces.
- Detach target, measurement, and graph views; resize workspace panes; select targets; and filter devices by current or run-wide status.
- Switch the interface among EN, DE, ES, NL, PL, and CN. English (EN) is the default.

## Requirements

- Python 3.10 or newer.
- Tkinter, usually included with the official Windows Python installer. On Linux, install the distribution's Tk package if it is not present (for example, `python3-tk`).
- The system `ping` executable for local measurements.
- Optional: Paramiko for SSH features.
- Optional on the remote Linux host: `ping`, `ip` (or `arp`), and `tcpdump`. The SSH account must have permission to run the requested commands; packet capture commonly requires elevated privileges or suitable capabilities.

Install the optional SSH dependency:

```console
python -m pip install paramiko
```

## Run

From the repository directory:

```console
python pingee.py
```

The SSH fields and remote features are optional. Enter one address or hostname per line, or paste a supported device list, then select **Start monitoring**. Use **Language** in the toolbar to change the interface language.

## SSH monitoring

Enter the SSH host, username, and password. When credentials are present, SSH mode is enabled automatically. The **Test SSH** action checks authentication and reports the remote hostname. Remote ping, neighbor monitoring, and DHCP capture are independent features and can be used separately.

Credentials are kept in process memory for the current run. The current implementation accepts a previously unknown SSH host key for the session rather than saving it to a persistent known-hosts file. Review `SSHRemote._get_client` and configure host-key verification before using this application in an environment that requires strict server identity validation.

## Architecture overview

`pingee.py` contains the application and is intentionally usable as a single-file program:

1. **Parsing helpers** turn text inventories and command output into normalized records.
2. **Worker threads** run pings, read streamed DHCP output, and poll neighbor tables. They publish events to a thread-safe queue and never update Tk widgets directly.
3. **`SSHRemote`** owns the reusable Paramiko connection and dispatches asynchronous ping jobs over a limited number of persistent shell channels.
4. **`PingeeApp`** consumes events on Tk's main thread, updates in-memory histories, and renders tables, plots, and pop-out windows.

The module-level documentation and class/method docstrings describe concurrency, data lifetimes, platform assumptions, and individual responsibilities. The implementation keeps probe records in memory; measurement export is explicit and user initiated.

## Performance notes

A long timeout only affects probes that do not reply. Successful probes report as soon as the operating system or remote command completes. Each target waits its configured interval after its own preceding probe finishes. Local concurrency is bounded by the **Parallel processes** setting; remote concurrency is handled by the persistent SSH dispatcher pool.

Large target counts, short intervals, packet-capture streams, or high concurrency can still load the client, SSH host, firewall, or network. ICMP may be rate-limited or deprioritized by intermediate devices. The application does not impose a fixed target-count ceiling, but available memory, operating-system process limits, remote shell capacity, and network behavior set practical limits.

## Development and verification

Compile-check the single-file application with:

```console
python -m py_compile pingee.py
```

The project currently has no automated test suite. Parser functions are designed as standalone helpers and are good candidates for unit tests; the GUI requires a desktop-capable Tk environment for interactive verification.

When changing background work, preserve the rule that workers communicate with the interface only through the event queue. When adding visible text, add entries to both `TRANSLATIONS` and (for formatted status messages) `STATUS_TRANSLATIONS`.

## Repository publication checklist

Before publishing a public repository, review the SSH host-key behavior and all dependencies, confirm the intended license, and remove any local data or credentials from example files and commit history. No license is included yet; choose and add one if you want to grant others reuse rights. Do not commit real network inventories, passwords, or captured packet data.
