<div align="center">

# 🛡️ SENTINEL
### Enterprise-Grade Static Application Security Testing (SAST) & Automated Program Repair (APR) Engine for Python

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux | Windows](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/)
[![Engine: LibCST & AST](https://img.shields.io/badge/engine-LibCST%20%7C%20AST-orange.svg)](https://github.com/instagram/LibCST)

*Detect vulnerabilities, trace data-flow taints, and automatically patch insecure Python codebases—completely offline.*

</div>

---

## 🚀 Overview

**Sentinel** is a high-performance, offline-first SAST and Automated Program Repair (APR) platform engineered specifically for Python. Unlike traditional security linters that only report code smells and leave remediation to the developer, Sentinel surgically patches vulnerabilities in-place using Concrete Syntax Tree (CST) transformations while preserving your original indentation, comments, and file formatting.

Designed for enterprise environments, air-gapped systems, and CI/CD pipelines, Sentinel runs entirely locally without sending any telemetry or code to external cloud APIs.

---

## ✨ Key Features

*   **🔍 Advanced Abstract Syntax Tree (AST) Scanner:** Deep-inspects code structures to isolate critical code anti-patterns and unsafe functions (e.g., arbitrary code execution via `eval()`, command injection via `os.system()`).
*   **🌊 Taint-Tracking Data-Flow Engine:** Builds local control and data-flow graphs to track untrusted inputs (sources like `input()` or `sys.argv`) across multi-step variable assignments down to execution sinks.
*   **🛠️️ Lossless Automated Program Repair (APR):** Automatically refactors vulnerable constructs into secure alternatives (such as mapping `os.system()` to safe `subprocess.run()` calls with proper argument splitting) via Instagram's `libcst`.
*   **💻 Zero-Dependency Binary Distribution:** Available as a standalone compiled executable (`sentinel` for Linux, `sentinel.exe` for Windows) built via PyInstaller—no local Python runtime required for end-users.
*   **📊 Enterprise Reporting:** Generates colorized terminal diff previews and supports standardized security reporting outputs.

---

## 📂 Project Architecture

```text
sentinel-ast/
├── sentinel.py              # Main CLI entrypoint and orchestrator
├── parser_engine.py         # AST analysis and vulnerability matching engine
├── cst_remediator.py        # Lossless code transformation via LibCST
├── rule_remediator.py       # Vulnerability signature mapping rules
├── rules.json               # Configurable security rule definitions
├── test_vulnerable.py       # Testbed containing intentional vulnerabilities
└── dist/                    # Compiled standalone production binaries
```

---

## 📥 Installation & Usage

You can run Sentinel either as a developer from source or as an end-user via the standalone pre-compiled binary.

### Option A: Using the Standalone Executable (Recommended for Quick Scans)
Download the platform-specific binary directly from the [GitHub Releases](https://github.com/ashwinbiji/sentinel-ast/releases) page.

1. Place the `sentinel` (Linux) or `sentinel.exe` (Windows) binary anywhere on your machine.
2. Run a dry-run diff preview against any target script:
   ```bash
   ./sentinel target_script.py --diff
   ```
3. Apply automatic fixes in-place:
   ```bash
   ./sentinel target_script.py --apply
   ```

---

### Option B: Installing from Source (For Developers)

If you wish to modify the engine or inspect the raw codebase:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/ashwinbiji/sentinel-ast.git
   cd sentinel-ast
   ```

2. **Create and Activate a Virtual Environment:**
   * **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   * **Windows:**
     ```cmd
     python -m venv venv
     venv\Scripts\activate
     ```

3. **Install Package Dependencies:**
   ```bash
   pip install .
   ```

4. **Run the CLI Tool:**
   ```bash
   sentinel test_vulnerable.py --diff
   ```

---

## 🧪 Testing with Vulnerable Code

Sentinel includes test scripts to verify detection and remediation performance safely without executing payload code.

```bash
# Preview proposed security fixes
sentinel test_vulnerable.py --diff

# Apply safe patches directly to the file
sentinel test_vulnerable.py --apply
```

---

## 🛠️ Building Standalone Binaries (PyInstaller)

If you want to re-compile the source code into a portable binary yourself:

1. Ensure your virtual environment is active and PyInstaller is installed:
   ```bash
   pip install pyinstaller
   ```
2. Build the single-file executable:
   ```bash
   pyinstaller --onefile sentinel.py
   ```
3. Locate your compiled binary inside the `dist/` folder.

---

## 🤝 Contributing

Contributions, security rule additions, and feature enhancements are welcome. Please open an issue or submit a pull request for review.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
