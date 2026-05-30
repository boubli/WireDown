import os
import json
import logging
import threading
from typing import Dict, Any, List
from flask import Blueprint, request, jsonify

logger = logging.getLogger("wiredown.orchestration")

class OrchestrationAPI:
    def __init__(self, get_device_registry, get_isolated_ips):
        """
        Initializes the Orchestration API.
        get_device_registry: Callable returning the current device registry (dict).
        get_isolated_ips: Callable returning a list of currently isolated/blocked IPs.
        """
        self.get_device_registry = get_device_registry
        self.get_isolated_ips = get_isolated_ips
        
        self.blueprint = Blueprint('orchestration', __name__)
        
        self.shared_secret = os.environ.get("SHARED_SECRET", "default_secret_wiredown_99")
        _base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.environ.get("SECURITY_DB_PATH", os.path.join(_base_dir, "data", "network_security.json"))
        self._lock = threading.Lock()
        
        self._setup_routes()
        self._ensure_db()

    def _ensure_db(self):
        """Ensure the data directory and db file exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        if not os.path.exists(self.db_path):
            self._save_db({"nodes": {}, "threats": []})

    def _load_db(self) -> Dict:
        """Load the persistence database."""
        with self._lock:
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Failed to load security DB: %s", e)
                return {"nodes": {}, "threats": []}

    def _save_db(self, data: Dict):
        """Save the persistence database."""
        with self._lock:
            try:
                with open(self.db_path, "w") as f:
                    json.dump(data, f, indent=4)
            except Exception as e:
                logger.error("Failed to save security DB: %s", e)

    def _verify_secret(self, req) -> bool:
        """Verify the SHARED_SECRET header."""
        auth_header = req.headers.get("X-Wiredown-Secret")
        return auth_header == self.shared_secret

    def _setup_routes(self):
        
        @self.blueprint.route("/api/orchestration/register", methods=["POST"])
        def register_node():
            if not self._verify_secret(request):
                return jsonify({"error": "Unauthorized"}), 401
                
            data = request.get_json() or {}
            mac = data.get("mac")
            ip = data.get("ip")
            role = data.get("role", "SENSOR")
            
            if not mac or not ip:
                return jsonify({"error": "mac and ip are required"}), 400
                
            db = self._load_db()
            
            # Register in persistence DB
            db["nodes"][mac] = {
                "ip": ip,
                "role": role,
                "status": "active",
                "registered_at": __import__('datetime').datetime.utcnow().isoformat()
            }
            self._save_db(db)
            
            logger.info("Orchestration: Registered %s node %s (%s)", role, mac, ip)
            return jsonify({"status": "success", "message": "Node registered"}), 200

        @self.blueprint.route("/api/orchestration/sync", methods=["GET"])
        def sync_rules():
            if not self._verify_secret(request):
                return jsonify({"error": "Unauthorized"}), 401
                
            # Combine isolated IPs from active memory and persisted threats
            isolated_ips = self.get_isolated_ips()
            
            db = self._load_db()
            persisted_threats = db.get("threats", [])
            
            # Update DB with new threats
            new_threats = list(set(isolated_ips + persisted_threats))
            if len(new_threats) > len(persisted_threats):
                db["threats"] = new_threats
                self._save_db(db)
                
            logger.info("Orchestration: Synced %d threat rules to peer", len(new_threats))
            
            return jsonify({
                "status": "success",
                "threats": new_threats
            }), 200

def register_orchestration(app, get_device_registry, get_isolated_ips):
    """Factory function to register the orchestration blueprint."""
    api = OrchestrationAPI(get_device_registry, get_isolated_ips)
    app.register_blueprint(api.blueprint)
    return api
