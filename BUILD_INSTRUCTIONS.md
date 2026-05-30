# WireDown Build & Execution Instructions

WireDown consists of a Rust-based Data Plane (`wd-engine`) and a Python-based Control Plane. Below are instructions for building and running both components.

---

## 1. Building the Data Plane (`src/engine/`)

The data plane requires the Rust toolchain and target libraries. It compiles to a static, optimized binary that relies on raw socket access (`AF_PACKET`).

### Requirements
- Rust stable toolchain
- `musl-tools` and `libpcap-dev` libraries (for static linking on Linux)

### Compilation Steps
You can use the provided build script helper which installs dependencies and compiles the binary automatically:

```bash
# Compile and install to /usr/local/bin
INSTALL=1 bash src/engine/build.sh
```

Alternatively, compile manually with cargo:
```bash
cd src/engine
cargo build --release --target x86_64-unknown-linux-musl
```

---

## 2. Running the Control Plane (`src/api/`)

The control plane is a Python/Flask application wrapped in a Uvicorn ASGI envelope.

### Requirements
- Python 3.11+
- Virtual environment (`venv`)

### Setup and Execution
1. Create a Python virtual environment and install requirements:
   ```bash
   cd src/api
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start the unified ASGI app using Uvicorn:
   ```bash
   python server.py
   ```
   This initializes the SQLite database, provisions default admin credentials (printed once in the server logs), and connects to the Unix Domain Socket bridge at `/run/wiredown.sock`.
