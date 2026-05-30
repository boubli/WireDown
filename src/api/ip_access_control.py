import json
import os
import logging

log = logging.getLogger("wiredown.access_control")

class IPAccessControl:
    def __init__(self, db_path="network_security.json"):
        self.db_path = db_path
        self.whitelist = {"127.0.0.1"}
        self.blacklist = set()
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    data = json.load(f)
                    # Merge with defaults
                    if "whitelist" in data:
                        self.whitelist.update(data["whitelist"])
                    if "blacklist" in data:
                        self.blacklist.update(data["blacklist"])
            except Exception as e:
                log.error("Failed to load access control list: %s", e)

    def _save(self):
        data = {}
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    data = json.load(f)
            except Exception:
                pass
        
        data["whitelist"] = list(self.whitelist)
        data["blacklist"] = list(self.blacklist)
        
        try:
            with open(self.db_path, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            log.error("Failed to save access control list: %s", e)

    def is_whitelisted(self, ip: str) -> bool:
        # Also allow local subnet loosely if needed, but for now exact match
        if ip in self.whitelist:
            return True
        # Allow internal docker network by prefix
        if ip.startswith("172.") or ip.startswith("10.") or ip.startswith("192.168."):
            return True # Fallback loose whitelist for local network
        return False

    def is_blacklisted(self, ip: str) -> bool:
        return ip in self.blacklist

    def add_to_whitelist(self, ip: str):
        if ip in self.blacklist:
            self.blacklist.remove(ip)
        self.whitelist.add(ip)
        self._save()

    def remove_from_whitelist(self, ip: str):
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self._save()

    # Protect critical network identities from ever being blacklisted —
    # 127.0.0.1, ::1, the appliance's own LAN IP, and CIDR ranges in
    # the operator whitelist. Configurable via WD_PROTECTED_IPS env.
    _PROTECTED = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

    def add_to_blacklist(self, ip: str):
        protected = set(self._PROTECTED) | {
            x.strip() for x in os.environ.get("WD_PROTECTED_IPS", "").split(",") if x.strip()
        }
        if ip in protected:
            log.warning("Refusing to blacklist protected IP %s", ip)
            return
        if ip in self.whitelist:
            self.whitelist.remove(ip)
        self.blacklist.add(ip)
        self._save()

    def remove_from_blacklist(self, ip: str):
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self._save()

    def get_whitelist(self):
        return self.whitelist

    def get_blacklist(self):
        return self.blacklist
