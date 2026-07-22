# SecurePulse — Password Strength Meter

A Flask web app to check password strength, generate secure passwords, and
crowd-source weak patterns that improve detection for every user.

## Features

- **Live strength check** — powered by `zxcvbn` (the algorithm behind
  Dropbox's password meter), plus a shared denylist of contributed weak
  patterns. Shows score, crack-time estimate, entropy, a criteria checklist,
  and concrete suggestions. Passwords are analyzed in memory only — never
  logged, stored, or persisted anywhere.
- **Password generator** — random (customizable length/character sets),
  passphrase (Diceware-style word combos), or a custom template pattern
  (e.g. `Llll-dddd-Llll-s`), all using Python's `secrets` CSPRNG.
- **Community patterns** — anyone can contribute a weak pattern (plain text
  or `/regex/`) that instantly strengthens the checker for every concurrent
  user, no restart required.
- **Multi-user safe** — stateless per-request handling and a shared SQLite
  store mean many people can use the app at the same time without
  interfering with each other.
- **URL shortener** — anonymous, Bitly-style short links with optional custom
  names, stored forever in the same SQLite database (see Data & backups
  below). Each browser remembers the links *it* created (for click counts and
  deletion) via localStorage — there's no login system.
- **Self-healing when run via `run_server.ps1`** — restarts itself within 5
  seconds if it ever crashes, and can start automatically at every Windows
  logon with zero admin rights required (see Keeping it running below).

## Setup

```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5050 (default port; override with `PORT`/`HOST`
env vars, e.g. `set PORT=8081 && python app.py`).

### Custom local domain (securepulse.dostcalabarzon.ph)

For solo use, this app can be mapped to a friendly hostname via the Windows
hosts file (`C:\Windows\System32\drivers\etc\hosts`):

```
127.0.0.1    securepulse.dostcalabarzon.ph
```

That only affects DNS resolution on this one machine.

### Serving colleagues on the office LAN

This machine's IP is `192.168.2.35`, and `securepulse.dostcalabarzon.ph` is
now a pfSense DNS **host override** pointing there too — so anyone on the
same office WiFi resolves that name straight to this machine, the same way
`lumina.dostcalabarzon.ph` already does. Two things this requires:

1. **The app must listen on the LAN interface, not just loopback.** Running
   plain `python app.py` only binds `127.0.0.1`, which colleagues cannot
   reach — you'll need `HOST=0.0.0.0` (see below).
2. **Use `waitress`, not the Flask dev server, once real people depend on
   it.** The dev server's debugger is fine solo on `127.0.0.1`, but
   `app.py` now refuses to start with `FLASK_DEBUG=1` on any non-loopback
   host — it would let anyone on the WiFi who can trigger an error run code
   on this machine. `waitress` has no such debugger and handles concurrent
   users properly:

```bash
waitress-serve --listen=0.0.0.0:5050 app:app
```

Colleagues then reach it at **http://securepulse.dostcalabarzon.ph:5050**.

**Worth knowing, now that this leaves your machine:** traffic between a
colleague's browser and this server is plain HTTP on the local network —
not encrypted. Anyone else on the same WiFi could in principle sniff a
password someone types into the checker in transit (nothing is ever stored
server-side, but it *does* cross the network now, unlike solo loopback use).
If that matters for your office's threat model, put this behind HTTPS (e.g.
a reverse proxy with an internal cert) before wider rollout. Also note the
"add/remove community pattern" and shortened-link endpoints have no
authentication — anyone who can reach the app can add or delete entries.

## Keeping it running (self-healing + auto-start)

Running `waitress-serve` by hand only lasts until that terminal closes. For
something colleagues depend on, use `run_server.ps1` instead — it wraps
`waitress` in a loop that restarts it within 5 seconds of any crash, and
also backs up the database once a day before each (re)start.

**One-time setup (no admin rights needed):**

```powershell
powershell -ExecutionPolicy Bypass -File install_startup.ps1
```

This copies a small hidden launcher into your own Windows Startup folder
(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`). From your next
logon onward, SecurePulse starts automatically in the background — no
console window, no manual step — and keeps itself alive after that. To turn
it off again: `install_startup.ps1 -Uninstall`.

**To start it right now, without waiting for your next logon**, double-click
`run_server_hidden.vbs` in File Explorer yourself (important: it has to be
launched from your own desktop session — a script *you* double-click keeps
running independently; anything launched by an automated tool inside a
terminal session tends to get cleaned up when that session ends, which is
why "start it in a terminal and leave it" doesn't hold up over time).

If you ever get admin/IT access to this machine, an even more robust option
is a real Windows Service (e.g. via NSSM) or a Task Scheduler task with "run
whether user is logged on or not" — those survive even without an
interactive logon at all, not just crashes.

## Data & backups

Community patterns and shortened links live in `instance/patterns.db`
(SQLite) and are kept indefinitely — nothing expires or gets cleaned up
automatically. That file **is** the data; don't delete it.

When started via `run_server.ps1`, a dated copy is also kept in
`instance/backups/patterns-YYYY-MM-DD.db` once per day (last 30 days are
kept, older ones pruned automatically). If the live database is ever lost or
corrupted, restore the most recent file from `instance/backups/` by copying
it back to `instance/patterns.db` while the server is stopped.
