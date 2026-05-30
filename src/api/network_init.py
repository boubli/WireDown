import logging
import socket
import struct
import os

try:
    from scapy.all import conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("wiredown.network_init")

def get_primary_network_info():
    """
    Auto-discovers the primary LAN interface, IP address, gateway, and subnet.
    Returns a dictionary with the configuration, or defaults if it fails.
    """
    
    # Check for manual overrides
    force_ip = os.environ.get("FORCE_BIND_IP")
    if force_ip:
        logger.info("FORCE_BIND_IP is set. Using manual override: %s", force_ip)
        return {
            "interface": os.environ.get("GUARDIAN_INTERFACE", "br0"),
            "local_ip": force_ip,
            "gateway_ip": "192.168.8.1",  # generic fallback
            "subnet": os.environ.get("GUARDIAN_SUBNET", "192.168.8.0/24")
        }

    info = {
        "interface": "br0",
        "local_ip": "0.0.0.0",
        "gateway_ip": "0.0.0.0",
        "subnet": "192.168.8.0/24"
    }

    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available. Cannot auto-discover network routing. Using fallbacks.")
        return info

    try:
        # Get the default route to 0.0.0.0 (the internet)
        # conf.route.route("0.0.0.0") returns tuple: (iface, gw, ip)
        route = conf.route.route("0.0.0.0")
        iface = route[0]
        gw = route[1]
        ip = route[2]
        
        info["interface"] = iface
        info["local_ip"] = ip
        info["gateway_ip"] = gw
        
        # Determine the subnet using Scapy's routing table
        routes = conf.route.routes
        # routes is a list of (net, mask, gw, iface, output_ip, metric)
        for r in routes:
            r_net, r_mask, r_gw, r_iface, r_ip, _ = r
            if r_iface == iface and r_ip == ip and r_gw == '0.0.0.0':
                # Convert net and mask to string representation
                net_str = socket.inet_ntoa(struct.pack("!I", r_net))
                
                # Calculate CIDR suffix
                mask_bin = bin(r_mask).count("1")
                info["subnet"] = f"{net_str}/{mask_bin}"
                break
        
        logger.info("Dynamic System Initialization complete:")
        logger.info("  Interface: %s", info["interface"])
        logger.info("  Local IP:  %s", info["local_ip"])
        logger.info("  Gateway:   %s", info["gateway_ip"])
        logger.info("  Subnet:    %s", info["subnet"])
        
    except Exception as e:
        logger.error("Failed to auto-discover network info: %s", str(e))
        logger.warning("Falling back to default interface 'br0' and wildcard IP '0.0.0.0'")

    return info
