# Run APKCheck Lab in Docker (Linux Intel / amd64)

This image targets **`linux/amd64`** so it runs on Intel/AMD Linux servers and desktops.  
You can also build it from Apple Silicon with Docker Buildx (QEMU).

## What you get

| Component | In container |
|-----------|----------------|
| `apkcheck` CLI | yes |
| Lab UI + API (`:8787`) | yes |
| Java 17 + apktool + jadx | yes |
| `adb` (platform-tools) | yes |
| Full Android Emulator / system images | **no** (use host emulator/device) |
| MCP (`apkcheck mcp`) | yes (stdio) |

## Preferred: deploy with `mdc` (tool laptop)

Containers run on **`armin@13.0.0.216`** (Linux Intel). Your Mac only runs the CLI.

Compose bind-mounts the host Divar workspace (so **Runs** can play real recordings):

`/home/armin/Dropbox/coding/sec/divar-lab` → `/data/lab`

Override with `APKCHECK_LAB_HOST_DIR=...` if needed. `network_mode: host` exposes UI on `:8787` and lets `adb` reach host emulators.

Compose also mounts the **host Android SDK** (`/home/armin/Android/Sdk`), **AVD config** (`/home/armin/.android`), and **`/dev/kvm`** so Lab can start/stop the emulator on the laptop (not on the Mac). Install once with `scripts/setup-laptop-emulator.sh`. After recorded scenarios, Lab wipe+cold-boots (`fresh_emulator`).

Obsidian: `03 Dev/Ask/README.md` · `03 Dev/APKCheck/APK-Lab.md`  
Tool: `coding/manage-docker-container` → `mdc`

```bash
cd apkcheck

# Point docker/compose at the laptop
mdc on    # DOCKER_CONTEXT=mdc-lab → ssh://armin@13.0.0.216

# Build amd64 on Mac Desktop, then load onto laptop (once / after rebuild)
docker --context desktop-linux compose build
docker --context desktop-linux save apkcheck:0.6.1 \
  | ssh armin@13.0.0.216 docker load

# One-time on laptop (KVM + AVD Pixel_8_API_34)
ssh armin@13.0.0.216 ./scripts/setup-laptop-emulator.sh   # or scp the script

# Start Lab on the laptop
mdc compose up -d lab
curl -s http://13.0.0.216:8787/api/health
curl -s http://13.0.0.216:8787/api/runtimes
# → http://13.0.0.216:8787 · Devices should show 1 AVD

# Stop Lab on laptop
mdc compose down

# Switch docker back to this Mac
mdc off
```

**Do not** keep Lab on Mac Docker Desktop — remove with:

```bash
mdc off
docker --context desktop-linux compose down -v
docker --context desktop-linux rmi apkcheck:0.6.1
```

## Quick start (on the Linux host itself)

```bash
cd apkcheck
docker compose build
docker compose up -d lab
xdg-open http://127.0.0.1:8787
```

Helper (when docker already targets the host):

```bash
./scripts/docker-lab build
./scripts/docker-lab up
./scripts/docker-lab doctor
```

Health check:

```bash
curl -s http://127.0.0.1:8787/api/health
```

## Persist / use a host workspace

Default compose uses volume `apkcheck-lab-data`.

Bind-mount your Divar (or any) workspace instead — edit `docker-compose.yml`:

```yaml
volumes:
  - /path/to/divar-lab:/data/lab
```

Then:

```bash
docker compose up -d lab
```

## CLI inside the container

```bash
docker compose run --rm cli doctor
docker compose run --rm cli lab import /work/app.apk --workspace /data/lab
docker compose run --rm cli version
```

Or:

```bash
docker run --rm -it --platform linux/amd64 \
  -v "$PWD/divar-lab:/data/lab" \
  apkcheck:0.6.1 doctor
```

## Connect adb to a host emulator / USB device (Linux)

The container does **not** ship a full emulator. For validate / record / security:

### Option A — host network (simplest on Linux)

```bash
# On the host: start emulator or plug phone, confirm:
adb devices

# Run Lab with host networking so container adb talks to host adb server
docker run --rm -it --platform linux/amd64 --network host \
  -v "$PWD/divar-lab:/data/lab" \
  apkcheck:0.6.1 lab ui --workspace /data/lab \
  --ui /opt/apkcheck/web/dist --addr :8787 --no-open
```

### Option B — TCP adb server

```bash
# Host
adb kill-server
adb -a nodaemon server start   # listen on all interfaces :5037  (lab only!)

# Compose: uncomment in docker-compose.yml
# ADB_SERVER_SOCKET: tcp:host.docker.internal:5037
```

Firewall: only expose `5037` on trusted lab networks.

## Build on Apple Silicon for Linux Intel

```bash
docker buildx create --use --name apkcheck-builder 2>/dev/null || true
docker buildx build --platform linux/amd64 -t apkcheck:0.6.1 --load .
# or simply:
docker compose build   # compose already sets platform: linux/amd64
```

### Move the image to a Linux Intel machine

```bash
# On build machine
docker save apkcheck:0.6.1 | gzip > apkcheck-0.6.1-amd64.tar.gz
scp apkcheck-0.6.1-amd64.tar.gz user@linux-host:~/

# On Linux Intel host
gunzip -c apkcheck-0.6.1-amd64.tar.gz | docker load
# copy docker-compose.yml (or whole repo), then:
docker compose up -d lab
```

Or push to a registry:

```bash
docker buildx build --platform linux/amd64 -t YOUR_REGISTRY/apkcheck:0.6.1 --push .
```

## MCP from Docker

MCP is stdio — point the client at Docker:

```json
{
  "mcpServers": {
    "apkcheck": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "-v", "/path/to/divar-lab:/data/lab",
        "apkcheck:0.6.1", "mcp"
      ]
    }
  }
}
```

## Limits (honest)

| Want | Reality in Docker |
|------|-------------------|
| Lab UI / import / rebuild / hunt / security catalog | Works |
| Emulator boot inside container | Not included (heavy; needs KVM + system images) |
| Screen recording | Needs a device/emulator reachable via `adb` |
| GPU emulator | Use host emulator + Option A/B above |

## Troubleshoot

```bash
docker compose logs -f lab
docker compose run --rm cli doctor
docker run --rm --platform linux/amd64 apkcheck:0.6.1 version
```

If UI assets missing: rebuild image (UI is compiled in the Dockerfile `ui` stage).
