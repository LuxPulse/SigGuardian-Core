<h1 align="center">🛡️ SigGuardian-X v1.0</h1>
<p align="center"><em>Environment-Locked Execution for Sensitive Tools</em></p>
<p align="center">
  <img src="https://img.shields.io/badge/status-stable-green?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
</p>

---

## 🔍 Overview

**SigGuardian-X** is a lightweight execution security layer that restricts your application from running outside of trusted environments.  
It ensures code safety through a signed verification process — based on environmental identifiers — before any logic is allowed to execute.

---

## 🚀 Features

- 🔒 Environment-bound execution (`MAC`, `UUID`, `SSID`, `filename`)
- 🧩 Signed and encrypted configuration (`sig.guard`)
- ❌ Blocks unknown or tampered execution contexts
- ⚙️ Easy integration with Rust-based tools

> This release is focused on minimal, safe, and high-assurance execution control.  
> ⚠️ Advanced capabilities are reserved for future versions.

---

## 📦 Use Cases

- Internal developer utilities
- Limited-access software tools
- Security-focused applications
- Executables deployed on specific machines only

---

## ⚙️ Getting Started

### 1. 🔧 Build Signature

```bash
sigguardian build \
  --macs "AA:BB:CC:DD:EE:FF" \
  --uuids "123e4567-e89b-12d3-a456-426614174000" \
  --ssid "Trusted_WiFi" \
  --filename "your_tool" \
  --tool-name "MySecureApp" \
  --self-destruct \
  --output sig.guard
