<h1 align="center">📁 Internal Source Structure</h1>
<p align="center"><code>SigGuardian-X v1.0 • MVP Core Layout</code></p>

---

## 🧬 Overview

This document describes the internal structure of the SigGuardian-X source code.  
The layout reflects an MVP version with core modules separated by responsibility.

---

## 📦 Directory Tree

src/ ├── lib.rs                      # Root logic – entry point to guardian engine ├── constants.rs                # Static configuration & constants (paths, values, etc.) ├── command_center.rs           # CLI command parsing and dispatch system ├── auto_purge.rs               # Self-destruction logic for unauthorized execution ├── system.rs                   # System identity gathering (MAC, UUID, hostname...) ├── remote_control.rs           # WebSocket interface for remote control & ops ├── geolocation.rs              # Retrieves IP info and location data ├── advanced_threat_detection.rs# Environment analysis (virtualization, VPN, tampering) ├── bin/ │   └── sigguardian.rs          # CLI binary entry point

---

## 🔍 Module Descriptions

- `lib.rs`  
  Central guardian interface. Coordinates all environment checks, signature loading, and failsafe logic.

- `constants.rs`  
  Contains predefined values used across modules (e.g. default file names, timeouts, paths).

- `command_center.rs`  
  Manages `sigguardian` CLI commands like `build`, `verify`, `purge`, `control`, and routes arguments.

- `auto_purge.rs`  
  Defines the logic that wipes files, cleans traces, or terminates execution in hostile environments.

- `system.rs`  
  Collects system-level identifiers (MAC, UUID, hostname, uptime) and generates fingerprints.

- `remote_control.rs`  
  Handles incoming control messages (e.g. `purge`, `status`, `shutdown`) via WebSocket interface.

- `geolocation.rs`  
  Retrieves and caches external IP address, geolocation data, and provider info from APIs.

- `advanced_threat_detection.rs`  
  Performs virtualization checks (VM, Docker, sandbox), reverse engineering tools, DNS leaks, and more.

- `bin/sigguardian.rs`  
  The compiled CLI interface — main binary run by the user or administrator.

---

## ⚠️ Notes

- This structure follows a **modular security-first design**.
- Each core layer is isolated for clarity and future extensibility.
- Additional submodules (e.g. logging, telemetry) can be added later without breaking the core.

---

<p align="center"><strong>🛡️ Trust is earned — by code, context, and configuration.</strong></p>