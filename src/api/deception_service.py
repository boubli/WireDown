import logging
import os
import pathlib
from typing import Dict, Any

logger = logging.getLogger("wiredown.deception_service")

class DeceptionService:
    def __init__(self, honeypot_fs_path: str):
        self.fs_path = pathlib.Path(honeypot_fs_path)

    def inject_honeytoken(self, filename: str, content: str) -> bool:
        """Dynamically injects a trackable decoy file into the honeypot directory."""
        try:
            self.fs_path.mkdir(parents=True, exist_ok=True)
            target = self.fs_path / filename
            # Ensure target parent subdirectory exists (e.g. for .ssh/id_rsa)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            logger.info("Injected honeytoken file: %s", filename)
            return True
        except Exception as e:
            logger.error("Failed to inject honeytoken file %s: %s", filename, str(e))
            return False

    def select_persona(self, threat_status: str) -> Dict[str, Any]:
        """Returns the terminal configuration settings corresponding to the threat state."""
        if threat_status == "attacker":
            return {
                "persona": "warnings_active",
                "motd_banner": (
                    "\r\n\033[1;31m[CRITICAL INTRUSION ALERT]\033[0m\r\n"
                    "WARNING: Your IP identity and MAC have been flagged by the Active Defense System.\r\n"
                    "Traceback initiated. Disconnect immediately.\r\n\r\n"
                )
            }
        else:
            return {
                "persona": "netgate_decoy",
                "motd_banner": (
                    "Welcome to NetGate Pro R4500 Enterprise OS (v9.4.2)\r\n"
                    "Authorized administrators only.\r\n\r\n"
                )
            }
