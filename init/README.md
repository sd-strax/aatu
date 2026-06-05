# init/ — platform service hooks

Drafts for running aatu as a system service. Polished templates for the OSS
launch (Phase H); useful today for anyone who wants the supervisor to come
back on reboot.

Both templates assume the `aatu` binary is installed at `/usr/local/bin/aatu`
(adjust the `ExecStart` / `ProgramArguments` if you put it elsewhere) and
that `~/.aatu/` is writable by the user running the service.

## macOS (launchd)

User-scope service so the supervisor runs as you, with access to `~/.aatu/`:

```bash
# 1. Install the binary
cp bin/aatu /usr/local/bin/aatu

# 2. Install the launchd plist
mkdir -p ~/Library/LaunchAgents
cp init/launchd/com.aatu.supervisor.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.aatu.supervisor.plist

# 3. Tail the logs
tail -f /tmp/aatu.log
```

To stop / unload:

```bash
launchctl unload ~/Library/LaunchAgents/com.aatu.supervisor.plist
```

Or just `aatu stop` from any shell — the plist's `KeepAlive` is set with
`SuccessfulExit=false`, so a clean stop (exit 0) won't be auto-restarted.

## Linux (systemd, user scope)

```bash
# 1. Install the binary
sudo cp bin/aatu /usr/local/bin/aatu

# 2. Install the systemd unit (user scope)
mkdir -p ~/.config/systemd/user
cp init/systemd/aatu.service ~/.config/systemd/user/

# 3. Enable + start
systemctl --user daemon-reload
systemctl --user enable --now aatu.service

# 4. Status / logs
systemctl --user status aatu.service
journalctl --user -u aatu.service -f
```

To stop / disable:

```bash
systemctl --user stop aatu.service
systemctl --user disable aatu.service
```

For system-scope (run as root, survives logout), drop the unit at
`/etc/systemd/system/aatu.service` and `systemctl enable --now aatu.service`
instead. Adjust `User=` and `Group=` in the unit, and make sure the data
directory (`~/.aatu/` by default) is reachable as that user.

## Windows

Deferred. The supervisor itself works on Windows (the components have
cross-platform support in `supervisor.Keycloak` for the OS-specific JRE
path); a Windows Service wrapper (NSSM, sc.exe, or a Go-based wrapper)
lands in Phase H if there's demand.

## Status

These templates are drafts. Validated locally on macOS only; Linux
validation comes during Phase H release engineering when we have CI
running against per-OS VMs.
