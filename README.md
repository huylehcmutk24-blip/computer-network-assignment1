# StreamCollab

StreamCollab is the CO3094 Assignment 1 application of Group 8 (class CC02): a
self-hosted client-server collaboration tool for a LAN. Users log in, see who is
online, chat in public or in private, and send files of any type. Chat, files and
acknowledgements travel over UDP through our own application protocol (streams,
sequence numbers, sliding window, selective retransmission, simplified CUBIC,
Fernet encryption); TCP carries only login and control. Clients find the server
with a UDP broadcast. Each client serves its browser interface through a small
local HTTP bridge (Python's standard `http.server`, bound to 127.0.0.1).

The technical report is `docs/report.pdf`; the assignment is `docs/assignment.pdf`.
All commands below run from the folder that contains `main.py`.

## 1. Requirements

- Python 3.12 or later on Windows, macOS or Linux.
- The `cryptography` package (the only runtime dependency).
- A web browser. Optional: Ruff for the style checks (`requirements-dev.txt`).

## 2. Install (once)

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt        # add -dev to get Ruff too
```

Windows (PowerShell):

```powershell
py -3.12 -m venv .venv          # or: python -m venv .venv, if python is 3.12 or later
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Every later command assumes the virtual environment is active (`python` is the venv one).

## 3. Create accounts (once)

```bash
python -m tools.demo_support provision --count 20
```

The tool asks for one password and writes `client01` to `client20` into
`config/secrets/` (ignored by git): `users.json` holds only salted scrypt hashes,
`server.keys.json` the server's keyring, and `clientNN.keys.json` the key of one
user. All 20 accounts share the password you typed; each has its own key. The
command refuses to overwrite existing files. To add one more account later, stop the server
and run `python -m tools.add_user <name>` (it prints the key ID and key file it created); to change
passwords: `python -m tools.reset_password client01`.

## 4. Run on one machine (four terminals)

Terminal 1, the server:

```bash
python main.py server --host 127.0.0.1
```

Terminals 2, 3 and 4, one client each:

```bash
python main.py client --receive-dir downloads/client01 --log-path logs/client01.log

python main.py client --username client02 --key-id 2 --keyring config/secrets/client02.keys.json --http-port 8766 --receive-dir downloads/client02 --log-path logs/client02.log

python main.py client --username client03 --key-id 3 --keyring config/secrets/client03.keys.json --http-port 8767 --receive-dir downloads/client03 --log-path logs/client03.log
```

Open http://127.0.0.1:8765, http://127.0.0.1:8766 and http://127.0.0.1:8767 and log
in with the matching username (`client01`, `client02`, `client03`) and the password
from step 3. The badge in the top bar shows the connection state. Ctrl+C stops a
process cleanly.

## 5. Run on a LAN

On the server machine (allow TCP 9000, UDP 9001 and UDP 9002 in its firewall):

```bash
python main.py server
```

`config/server.example.json` binds `0.0.0.0`. Copy to each client machine the
project and **only that user's** key file `config/secrets/clientNN.keys.json`
(never `server.keys.json`). Then either let the client find the server by broadcast:

```bash
python main.py client --config config/client.lan.example.json
```

or give the address yourself: `python main.py client --host 0.0.0.0 --server 192.168.1.10`.
For other users add `--username clientNN --key-id NN --keyring config/secrets/clientNN.keys.json`.
`--server auto` broadcasts DISCOVER to 255.255.255.255:9002; the server answers
with its ports and the client logs in over the address the answer came from.
Broadcasts do not cross routers; across a VPN or subnet use `--server <IP>`.
The browser page always stays on 127.0.0.1 of the client machine.

## 6. What to try in the interface

1. A wrong password shows "Login denied (HTTP 403)".
2. After login every page lists the online users; the badge reads "Online, server <address>".
3. Public chat reaches everyone; a private message reaches only the chosen user.
   Your own line changes from "Sending" to "Server received".
4. Choose a file and a recipient: both pages show a progress bar; the receiver
   saves it in its `--receive-dir` only after the size and SHA-256 match.
5. Chat keeps working while a file is transferring.
6. Stop the server and start it again: clients reconnect by themselves within
   about a minute (the badge shows the attempts). Kill a client: the others see it
   leave and keep working.

## 7. Self check and measurements

```bash
python demo.py
```

runs a server and 20 clients in one process (real sockets, temporary accounts):
logins, 400 chat deliveries, ten files with one dropped datagram, and a logout.
It prints `DEMO PASS` and exits with 0, or `DEMO FAIL` with the reason.

The numbers in the report come from two hosts on one LAN: host A runs the server,
host B runs client01 to client03 and the scripts in `evidence/`. In short:

```bash
# host B, server running on host A; first: python -m pip install playwright and
# python -m playwright install chromium (on Linux, as root: install --with-deps chromium)
python evidence/browser_session.py --server <IP of A> --keep-client01   # S1 to S6
python evidence/run_remote.py --server <IP of A>                         # S5b, S7 to S16
# host A, server stopped
python evidence/run_local.py                                             # self check, Ruff, comments
# host A, after copying B's logs/ and evidence/out/ to measurements/B/logs/ and measurements/B/out/
python -m tools.collect_metrics --sender client01 --receiver client03 \
    --outsider client03 --remote client02
```

`run_remote.py` asks you to take host B's network link down and up and to restart the
server during its last script (`interruption_check.py`). `collect_metrics` reads the logs
and results of both hosts and writes `measurements/report/numbers.tex`, `summary.txt`
and `cwnd_trace.csv`; it refuses script results that were not produced against a server
on another host. Every script also runs alone, either against a server on another host
(`--server <IP>`) or, without `--server`, against a temporary server in the same process
(useful to try a script; such results are not used in the report). The outputs of the
run behind the report are in `evidence/out/`, `logs/` and `measurements/report/`.

| Script | What it shows |
|---|---|
| hol_check.py | chat is not delayed while a file chunk is missing (no head-of-line blocking) |
| encryption_check.py | no chat text, file data or password on the wire; every bit flip rejected |
| browser_session.py | S1 to S6: three client processes used through their web pages in a headless browser |
| concurrent_login.py | 19 logins at once (20 users with client01), addresses, 10 leave at once |
| resilience_check.py | TCP resets, silent sockets, killed client processes, receiver killed mid file |
| interruption_check.py | network link of the client host down for about 3 s and 20 s, server restart |
| discovery_check.py | UDP broadcast discovery and login over the LAN address |
| http_bridge_check.py | the local HTTP bridge and its status codes |
| machine_info.py, comment_count.py | machine description; docstring and comment counts |

Style checks (needs `pip install -r requirements-dev.txt`):

```bash
ruff format --isolated --check --line-length 100 --target-version py312 .
ruff check --isolated --line-length 100 --target-version py312 --select E4,E7,E9,F,I,UP,B,SIM,C4,C90 .
```

## 8. Project layout

| Path | Role |
|---|---|
| main.py, config.py | Entry point and command line flags; validated settings |
| protocol.py | Packet schema, JSON codec, TCP framing, size formula |
| transport.py, congestion.py | Reliable UDP (sequencing, ACKs, window, retransmission); CUBIC |
| security.py | Fernet packet protection, keyrings, scrypt password hashes |
| server.py, server_relay.py | Sessions, discovery, UDP binding, heartbeats, chat routing; file relay |
| client.py, files.py | Client core, discovery, auto-reconnect; file chunking and verification |
| web.py, ui/ | Local HTTP bridge (`http.server`); HTML, CSS and client-side JavaScript |
| demo.py, evidence/, tools/ | Self check; measurement scripts and their outputs; account tools, `collect_metrics.py` |
| docs/ | Report (`report.pdf`), the assignment and earlier design diagrams (`diagrams/`, `drawio/`, `figures/`, drawn before discovery was added) |

## 9. Settings

Defaults live in `config.py`; a JSON file (`--config`) overrides them and command
line flags override both. Unknown fields or wrong types are rejected at start.

| Setting (flag) | Default | Meaning |
|---|---|---|
| bind_host (`--host`) | 127.0.0.1 | Local address to bind; use 0.0.0.0 on a LAN |
| server_host (`--server`) | 127.0.0.1 | Server address for a client, or `auto` for broadcast discovery |
| tcp_port / udp_port | 9000 / 9001 | TCP control / UDP data |
| discovery_port (`--discovery-port`) | 9002 | UDP port of DISCOVER/ANNOUNCE |
| bridge_port (`--http-port`) | 8765 | Loopback port of the client's web page |
| max_datagram_bytes / chunk_size | 1200 / 256 bytes | Encrypted datagram limit / file chunk |
| window_packets / max_peer_pending | 8 / 64 | Sliding window / packets queued per peer |
| max_file_bytes / max_clients | 100 MiB / 20 | File size limit / sessions on the server |
| heartbeat_seconds / offline_seconds | 2 / 8 s | Heartbeat period / silence that ends a session |
| retry_initial / retry_max / max_retries | 0.5 s / 2 s / 5 | Retransmission backoff |

## 10. Troubleshooting

- "Login denied": wrong password, wrong user for this key file, the user is
  already online, or the server is full (the server gives one answer for all).
- "No server answered the discovery broadcast": the server is not running, UDP
  9002 is blocked, or the machines are on different subnets; use `--server <IP>`.
- "Address already in use": another server or client still runs on that port;
  stop it or pass other `--tcp-port`, `--udp-port` or `--http-port` values.
- A received file is never overwritten; rename the old one or use another `--receive-dir`.
- Chat is limited to 346 UTF-8 bytes per message (Vietnamese letters and emoji
  use several bytes); the page shows the limit under the message box.
