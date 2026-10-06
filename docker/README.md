# Docker strategy for apkcheck

## Lab UI / CLI image (Linux Intel)

See **[`docs/DOCKER.md`](../docs/DOCKER.md)** and root [`Dockerfile`](../Dockerfile) + [`docker-compose.yml`](../docker-compose.yml).

```bash
./scripts/docker-lab build   # linux/amd64
./scripts/docker-lab up      # http://127.0.0.1:8787
```

## Decompiler pin images

Prefer **shared JDK base + versioned tool artifacts**, not dozens of fat duplicate images.

```text
Tool Version Registry (configs/versions.yaml)
        ↓
Select exact pin (id + sha256 + source)
        ↓
Runner: local path  OR  docker image tag
        ↓
Isolated decompile into work/versions/<tool>/<id>/
        ↓
Parse Java → IR → compare vs Smali
```

## Rules

1. Never build or pull `:latest`.
2. Image tags must match pin ids (`apkcheck-cfr:0.152`).
3. Dockerfile labels record source URL + sha256.
4. ADB / USB device access stays on the **macOS host**, not inside Docker.

## Build examples

```bash
# CFR (artifact already vendored)
docker build -t apkcheck-cfr:0.152 -f docker/cfr/0.152/Dockerfile .

# Then set runner: docker for that pin in configs/versions.yaml
```
