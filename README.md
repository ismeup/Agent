# isMeUp Agent

A monitoring agent for [isMeUp](https://ismeup.net). Install it on your server to connect to the platform and report host availability.

---

## Table of Contents

- [Quick Install](#quick-install)
- [Running with Docker](#running-with-docker)
- [Running without Docker](#running-without-docker)
- [Environment Variables](#environment-variables)

---

## Quick Install

The fastest way to install the agent on a Linux server:

```bash
curl -sSL https://raw.githubusercontent.com/ismeup/Agent/main/install.sh -o install.sh
bash install.sh
```

The script will check that Docker and Git are available, clone the repository, build the image, run the interactive registration, and start the service.

> The installer requires an interactive terminal and will not work when piped directly (`curl ... | bash`).

---

## Running with Docker

### 1. Register the agent

Before the first run, register the agent — it will obtain an identity key and save it to `data/identity.key`.

```bash
mkdir -p data
docker compose run --rm agent --register
```

This starts an interactive session: enter your isMeUp account login/password and choose a name for the agent. The `data/identity.key` file is created automatically.

> If `identity.key` already exists, registration is skipped. Delete the file to register a new agent.

### 2. Run in the background

```bash
docker compose up -d
```

The container starts with `restart: always` — it will come back up automatically after a host reboot.

### Container management

```bash
# Follow logs
docker compose logs -f

# Stop
docker compose down

# Restart
docker compose restart agent
```

### Note on host networking

The agent runs with `network_mode: host` because the Wake On Lan check sends UDP broadcast packets to the local subnet, which is not possible from a Docker bridge network.

Trade-offs of host networking:

- The container shares the host's network namespace — there is no network isolation between the container and the host.
- Port mapping is not available. The agent only makes outbound connections, so no ports are exposed anyway.
- Host networking is not supported by Docker Desktop for macOS/Windows — `docker compose up` will fail there.

If you don't need the Wake On Lan check, you can remove the `network_mode: host` line from `docker-compose.yaml`; the agent works fine with the default bridge network.

---

## Running without Docker

### Requirements

- Python 3.10+
- `ping` (`iputils-ping` on Debian/Ubuntu)

### 1. Install

```bash
pip install .
```

Or build and install a wheel:

```bash
pip install hatch
hatch build
pip install dist/ismeup_agent-*.whl
```

### 2. Register the agent

```bash
mkdir -p data
ismeup-agent --register
```

The interactive session will ask for your login/password and an agent name. The key is saved to `data/identity.key`.

### 3. Run

One-off run in the terminal:

```bash
ismeup-agent
```

### 4. Run in the background with systemd

Create a unit file:

```bash
sudo nano /etc/systemd/system/ismeup-agent.service
```

Contents (replace `/home/user` with the actual path):

```ini
[Unit]
Description=isMeUp Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/ismeup-agent
Environment=AGENT_KEY_PATH=/home/user/ismeup-agent/data/identity.key
ExecStart=/home/user/.local/bin/ismeup-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ismeup-agent
```

Check status and logs:

```bash
sudo systemctl status ismeup-agent
sudo journalctl -u ismeup-agent -f
```

---

## Environment Variables

| Variable            | Default            | Description                                          |
|---------------------|--------------------|------------------------------------------------------|
| `AGENT_KEY_PATH`    | `data/identity.key`| Path to the identity key file                        |
| `ISMEUP_HOST`       | `ismeup.net`       | isMeUp server host                                   |
| `ISMEUP_PORT`       | `8787`             | isMeUp server port                                   |
| `ISMEUP_URL`        | `https://ismeup.net`| isMeUp API base URL                                 |
| `ENABLE_PORT_PROXY` | disabled           | Port forwarding feature; set to `1` to enable        |
| `ENABLE_WOL`        | enabled            | Wake On Lan feature; set to `0` to disable           |

Port forwarding (port proxy) is disabled by default. The agent accepts `port_proxy` operations from the server only when `ENABLE_PORT_PROXY` is set to `1` (also accepted: `true`, `yes`, `on`).

Wake On Lan is enabled by default. Set `ENABLE_WOL=0` (also accepted: `false`, `no`, `off`) to disable it.

When using Docker, set variables in a `.env` file next to `docker-compose.yaml`:

```env
ISMEUP_HOST=ismeup.net
ISMEUP_PORT=8787
ISMEUP_URL=https://ismeup.net
# Enable port forwarding (port proxy) feature
# ENABLE_PORT_PROXY=1
# Disable Wake On Lan (enabled by default)
# ENABLE_WOL=0
```
