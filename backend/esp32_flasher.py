import os
import re
import subprocess
import threading
import logging

log = logging.getLogger('wiredown.esp32_flasher')

FLASH_LOCK = threading.Lock()

_flash_state = {
    "status": "idle",
    "stdout": "",
    "stderr": "",
    "progress": 0
}

def get_flash_status() -> dict:
    return dict(_flash_state)

def configure_ino(ssid: str, password: str, backend_ip: str) -> str:
    template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "esp32_sensor", "esp32_sensor.ino"))
    build_dir = "/tmp/wiredown_build/esp32_sensor"
    out_path = os.path.join(build_dir, "esp32_sensor.ino")

    os.makedirs(build_dir, exist_ok=True)
    
    with open(template_path, "r") as f:
        content = f.read()

    # replace creds
    content = re.sub(r'const char\*\s*WIFI_SSID\s*=\s*".*?";', f'const char* WIFI_SSID      = "{ssid}";', content)
    content = re.sub(r'const char\*\s*WIFI_PASS\s*=\s*".*?";', f'const char* WIFI_PASS      = "{password}";', content)
    content = re.sub(r'const char\*\s*WS_SERVER_HOST\s*=\s*".*?";', f'const char* WS_SERVER_HOST = "{backend_ip}";', content)

    with open(out_path, "w") as f:
        f.write(content)

    log.info("Configured INO written to %s", out_path)
    return out_path

def detect_esp32_port() -> str | None:
    try:
        result = subprocess.run(
            ["arduino-cli", "board", "list", "--format", "json"],
            capture_output=True, text=True, check=True
        )
        import json
        data = json.loads(result.stdout)
        
        for port_info in data:
            # Look for typical ESP32 serial chips or just grab the first ttyUSB/ttyACM
            addr = port_info.get("port", {}).get("address", "")
            if "ttyUSB" in addr or "ttyACM" in addr:
                return addr
    except Exception as e:
        log.error("Failed to detect ESP32 port: %s", e)
    return None

def compile_and_flash(port: str = '/dev/ttyUSB0') -> dict:
    global _flash_state
    
    if not FLASH_LOCK.acquire(blocking=False):
        return {"status": "error", "message": "Flash already in progress"}

    build_dir = "/tmp/wiredown_build/esp32_sensor"
    
    def _run():
        global _flash_state
        try:
            _flash_state = {"status": "compiling", "stdout": "", "stderr": "", "progress": 10}
            log.info("Compiling ESP32 code...")
            
            # compile
            compile_cmd = ["arduino-cli", "compile", "--fqbn", "esp32:esp32:esp32", build_dir]
            res = subprocess.run(compile_cmd, capture_output=True, text=True)
            
            _flash_state["stdout"] += res.stdout
            _flash_state["stderr"] += res.stderr
            
            if res.returncode != 0:
                _flash_state["status"] = "error"
                log.error("Compilation failed:\n%s", res.stderr)
                return

            _flash_state = {"status": "flashing", "stdout": _flash_state["stdout"], "stderr": _flash_state["stderr"], "progress": 50}
            log.info("Flashing ESP32 on port %s...", port)
            
            # upload
            upload_cmd = ["arduino-cli", "upload", "--fqbn", "esp32:esp32:esp32", "--port", port, build_dir]
            res = subprocess.run(upload_cmd, capture_output=True, text=True)
            
            _flash_state["stdout"] += res.stdout
            _flash_state["stderr"] += res.stderr
            
            if res.returncode != 0:
                _flash_state["status"] = "error"
                log.error("Upload failed:\n%s", res.stderr)
                return
                
            _flash_state["status"] = "done"
            _flash_state["progress"] = 100
            log.info("ESP32 flashed successfully")
            
        except Exception as e:
            _flash_state["status"] = "error"
            _flash_state["stderr"] += str(e)
            log.error("Flash exception: %s", e)
        finally:
            FLASH_LOCK.release()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    
    return {"status": "started", "message": "Compilation and flash started in background"}
