# Agent Opulence / Blunderbussy framework

## Use of `bd` for task management

Use `bd` to manage all tasks. Make sure to create issues
to keep track of everything.

## Python tooling

Use `uv` for Python package management and running tests:
- `uv pip install <package>` - Install packages
- `uv run pytest` - Run tests
- `uv run python script.py` - Run scripts

## Container tooling

Use `podman` and `podman-compose` (not docker):
- `podman-compose up -d` - Start services
- `podman-compose ps` - List running containers
- `podman exec -it <container> <command>` - Execute in container

## Dame container builds

The Dame Dockerfile supports platform-specific tool groups via build arg:

```bash
# Linux target (default) - includes searchsploit
podman build --build-arg TARGET_PLATFORM=linux -t dame:linux -f infrastructure/dame/Dockerfile infrastructure/dame/

# Windows/AD target - includes evil-winrm, responder, ldap-utils, bloodhound
podman build --build-arg TARGET_PLATFORM=windows -t dame:windows -f infrastructure/dame/Dockerfile infrastructure/dame/
```

Core tools (always installed): nc, ping, traceroute, wget, socat, rlwrap, git, jq, dig, proxychains4, nbtscan, onesixtyone, snmpwalk
