# Fake SSH Honeypot Server
# Drops bots into a plain-text interactive shell that logs keystrokes.

import asyncio
import asyncssh
import logging
import os
import struct
import sys
import time
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger("wiredown.fake_ssh")

# Dynamic Honeypot Filesystem

import pathlib

FS_DIR = pathlib.Path(__file__).parent / "honeypot_fs"

# nosonar: intentional honeypot bait credentials
DEFAULT_PASSWORDS = """\
# Internal credentials — DO NOT SHARE
# Last updated: 2024-05-14

admin:admin123
root:toor
db_user:p@ssw0rd
backup_svc:Backup!2024
jenkins:j3nk1ns_Ci
deploy:d3pl0y_k3y_2024
monitoring:m0n1t0r#99"""

# nosonar: intentional honeypot bait environment file
DEFAULT_ENV = """\
# Application Environment Configuration
# WARNING: Keep this file secure!

APP_ENV=production
APP_DEBUG=false
APP_PORT=8080

DB_HOST=10.0.0.50
DB_PORT=5432
DB_NAME=app_production
DB_USER=app_svc
DB_PASSWORD=Pr0d_DB!s3cur3_2024

REDIS_URL=redis://10.0.0.51:6379/0
REDIS_PASSWORD=r3d1s_cl0ud_99

API_KEY=sk-proj-4f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c
API_SECRET=a8f2e1d4c7b6a9f3e2d1c4b7a6f9e8d2

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=prod-app-assets

SMTP_HOST=smtp.internal.corp
SMTP_USER=notifications@internal.corp
SMTP_PASSWORD=N0t1fy_Ml!2024

JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super_secret_signing_key
ENCRYPTION_KEY=c2VjcmV0X2VuY3J5cHRpb25fa2V5XzIwMjQ="""

# nosonar: intentional honeypot bait SSH key
DEFAULT_RSA_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA2mKqHD/DFo0PnL0V4wqiVCdMG6mUmXJKBNGnMHpJag0FfJTQJH
q8zLmxKoVerON5MjGYRyIxhDjIRkf0n9p3rkMB6GXVAE7RIxMlzrZqFNsKy2aG09d3sW1
M+xYZTjKEYCH5F6MUOL0GPMONCyGHB8w9dl8hZMnBFAqVgxfxcAAAIYzN6L+8zei/sAAA
AHc3NoLXJzYQAAAIEA2mKqHD/DFo0PnL0V4wqiVCdMG6mUmXJKBNGnMHpJag0FfJTQJH
q8zLmxKoVerON5MjGYRyIxhDjIRkf0n9p3rkMB6GXVAE7RIxMlzrZqFNsKy2aG09d3sW1
M+xYZTjKEYCH5F6MUOL0GPMONCyGHB8w9dl8hZMnBFAqVgxfxcAAAADAQABAAAAgDZ3Nx
NLcRLnOgNgxEYKDOJbLBqMdUINa/Aup7gg0SnNDwkHA3p2FJKBIvt07h2FMxK2GxKG/Ty
j2aS7PyQxGUCc/TRmEaVi+wRodAjHFjNpkfxFJZH9yG5BeL4K+y08B3oT3xmN/VOV3mhI
YudFaJJmK+75LBeF9FWRN5BhYBAAAAQQCqWu9pMxS/0OOL3Djp1Z5j3viH5w6h6N+s8N
p3VB7TZlD7N0P0ATnR5TzVGh7MGCV6CHqEuV0GKweRFEJYBf/JAAAAQEA8f2FIhIMGW/k
4x5HGf0G7YH3FOHcBQP1p6bRj15ovZaLF8JMT3J3K1P0UZnD0lBMGxNLno7PcNlMH0H+
3F3JcwAAAEEA5l1GqZBxpVBkFnhOJL1D5h8bBQ1SuCGfNz7gNP3tJ1V7F1Xb1VJEeSal6
QXQa5K8Rkf7P3MSuF1DhS3F9z/9wAAAA1kZXZAaG9uZXlwb3Q=
-----END OPENSSH PRIVATE KEY-----"""

# nosonar: intentional honeypot bait passwd file
DEFAULT_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
{user}:x:1000:1000:{user},,,:/home/{user}:/bin/bash
postgres:x:108:114:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
redis:x:109:115::/var/lib/redis:/usr/sbin/nologin"""

def _init_fs():
    """Ensure the honeypot_fs directory exists and has default bait."""
    FS_DIR.mkdir(parents=True, exist_ok=True)
    (FS_DIR / ".ssh").mkdir(exist_ok=True)
    
    if not (FS_DIR / "passwords.txt").exists():
        (FS_DIR / "passwords.txt").write_text(DEFAULT_PASSWORDS)
    if not (FS_DIR / ".env").exists():
        (FS_DIR / ".env").write_text(DEFAULT_ENV)
    if not (FS_DIR / ".ssh" / "id_rsa").exists():
        (FS_DIR / ".ssh" / "id_rsa").write_text(DEFAULT_RSA_KEY)
    if not (FS_DIR / "passwd").exists():
        (FS_DIR / "passwd").write_text(DEFAULT_PASSWD)
    if not (FS_DIR / "passwords.bak").exists():
        (FS_DIR / "passwords.bak").write_text("ENCRYPTED_BACKUP=true\nLAST_ROTATED=2024-05-12\n")
    if not (FS_DIR / "wallet.dat").exists():
        (FS_DIR / "wallet.dat").write_text("WALLET_VERSION=2\nCHECKSUM=deadbeefcafebabe\n")
    if not (FS_DIR / "vpn_config.ovpn").exists():
        (FS_DIR / "vpn_config.ovpn").write_text("client\nremote 10.0.0.1 1194\nproto udp\n")

# Initialize on module load
_init_fs()


# Ensure proper server host key exists
def _ensure_keys():
    key_path = FS_DIR / 'wiredown_ssh_host.key'
    if not key_path.exists():
        log.info("Generating new RSA host key for the server...")
        key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
        key.write_private_key(str(key_path))

_ensure_keys()

class FakeSSHSession:
    def __init__(self, session_id: str, client_ip: str, client_port: int):
        self.session_id = session_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = None
        self.password = None
        self.commands = []
        self.connected_at = datetime.now(timezone.utc)
        self.disconnected_at = None
        self.active = True

    @property
    def duration_seconds(self) -> float:
        end = self.disconnected_at or datetime.now(timezone.utc)
        return (end - self.connected_at).total_seconds()

    @property
    def command_count(self) -> int:
        return len(self.commands)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "username": self.username,
            "password": self.password,
            "commands": self.commands,
            "connected_at": self.connected_at.isoformat(),
            "disconnected_at": self.disconnected_at.isoformat() if self.disconnected_at else None,
            "active": self.active,
            "duration_seconds": round(self.duration_seconds, 2),
            "command_count": self.command_count,
        }


VIRTUAL_FS = {
    "/": {
        "type": "dir",
        "owner": "root",
        "group": "root",
        "mode": "drwxr-xr-x",
        "children": {
            "etc": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwxr-xr-x",
                "children": {
                    "passwd": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-rw-r--r--",
                        "size": 1280,
                        "content": "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n{user}:x:1000:1000::/home/{user}:/bin/bash\r\n"
                    },
                    "shadow": {
                        "type": "file",
                        "owner": "root",
                        "group": "shadow",
                        "mode": "-rw-r-----",
                        "size": 845,
                        "content": "root:$6$v.48271s$F4LwKqA48h1s9Dla04lsnKqlsa81s98djalhsa981hskalha1981hsalk8a2jshlaKla:19827:0:99999:7:::\r\n{user}:$6$m.18472a$sKla8194hsalkhjda9184hsklahjla9814hskljda9184hskljda8194hsklja194hsk:19827:0:99999:7:::\r\n"
                    },
                    "admin_panel.conf": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-rw-r--r--",
                        "size": 154,
                        "content": "# NetGate Pro Secure Administration Interface Link\r\nADMIN_URL=http://10.0.0.50:5000/secure_admin_v9\r\n"
                    }
                }
            },
            "var": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwxr-xr-x",
                "children": {
                    "www": {
                        "type": "dir",
                        "owner": "www-data",
                        "group": "www-data",
                        "mode": "drwxr-xr-x",
                        "children": {
                            "html": {
                                "type": "dir",
                                "owner": "www-data",
                                "group": "www-data",
                                "mode": "drwxr-xr-x",
                                "children": {
                                    "index.html": {
                                        "type": "file",
                                        "owner": "www-data",
                                        "group": "www-data",
                                        "mode": "-rw-r--r--",
                                        "size": 154,
                                        "content": "<html><body><h1>Under Construction</h1></body></html>\r\n"
                                    },
                                    "wp-config.php": {
                                        "type": "file",
                                        "owner": "www-data",
                                        "group": "www-data",
                                        "mode": "-rw-r-----",
                                        "size": 3214,
                                        "content": "<?php\r\ndefine( 'DB_NAME', 'wordpress_db' );\r\ndefine( 'DB_USER', 'wp_admin_user' );\r\ndefine( 'DB_PASSWORD', 'Wp_S3cur3_Db_P@ss_2025' );\r\ndefine( 'DB_HOST', 'localhost' );\r\ndefine( 'DB_CHARSET', 'utf8' );\r\n"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "opt": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwxr-xr-x",
                "children": {
                    "backups": {
                        "type": "dir",
                        "owner": "root",
                        "group": "root",
                        "mode": "drwxr-xr-x",
                        "children": {
                            "db_backup.sql": {
                                "type": "file",
                                "owner": "root",
                                "group": "root",
                                "mode": "-rw-------",
                                "size": 1048576,
                                "content": "-- MySQL dump 10.13  Distrib 8.0.32\r\n-- Host: localhost    Database: prod_db\r\n-- Tracking trigger token:\r\n-- SELECT http_get('http://10.0.0.50:5000/api/beacon?id=database_dump');\r\n-- SELECT LOAD_FILE('\\\\api-sync-auth-token-8472.wiredown.tech\\a');\r\n"
                            }
                        }
                    }
                }
            },
            "home": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwxr-xr-x",
                "children": {
                    "{user}": {
                        "type": "dir",
                        "owner": "{user}",
                        "group": "{user}",
                        "mode": "drwxr-xr-x",
                        "children": {
                            ".bash_history": {
                                "type": "file",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "-rw-------",
                                "size": 342,
                                "content": "cd /var/www/html\r\ncat config.php\r\nssh root@10.0.0.99\r\n# admin:SuperSecurePassword123\r\n./deploy.sh\r\n"
                            },
                            ".ssh": {
                                "type": "dir",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "drwx------",
                                "children": {
                                    "id_rsa": {
                                        "type": "file",
                                        "owner": "{user}",
                                        "group": "{user}",
                                        "mode": "-rw-------",
                                        "size": 1675,
                                        "content": "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn\r\nNhAAAAAwEAAQAAAIEA2mKqHD/DFo0PnL0V4wqiVCdMG6mUmXJKBNGnMHpJag0FfJTQJH\r\nq8zLmxKoVerON5MjGYRyIxhDjIRkf0n9p3rkMB6GXVAE7RIxMlzrZqFNsKy2aG09d3sW1\r\n-----END OPENSSH PRIVATE KEY-----\r\n"
                                    }
                                }
                            },
                            "network_architecture.pdf": {
                                "type": "file",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "-rwxr-xr-x",
                                "size": 8192,
                                "content": "%PDF-1.4\r\n% [CONFIDENTIAL] WireDown Network Topology Map\r\n"
                            },
                            "wallet.dat": {
                                "type": "file",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "-rw-r--r--",
                                "size": 1024,
                                "content": "WALLET_VERSION=2\r\nCHECKSUM=deadbeefcafebabe\r\n"
                            },
                            "passwords.bak": {
                                "type": "file",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "-rw-r--r--",
                                "size": 512,
                                "content": "ENCRYPTED_BACKUP=true\r\nLAST_ROTATED=2024-05-12\r\n"
                            },
                            "vpn_config.ovpn": {
                                "type": "file",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "-rw-r--r--",
                                "size": 256,
                                "content": "[Alert] Canary Token triggered. Target MAC address locked.\r\n"
                            },
                            "backup_sync.sh": {
                                "type": "file",
                                "owner": "{user}",
                                "group": "{user}",
                                "mode": "-rwxr-xr-x",
                                "size": 142,
                                "content": "#!/bin/bash\r\n# Automated backup verification sync script\r\nping -c 1 api-sync-auth-token-8472.wiredown.tech > /dev/null\r\necho 'Sync complete.'\r\n"
                            }
                        }
                    }
                }
            },
            "root": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwx------",
                "children": {
                    ".aws": {
                        "type": "dir",
                        "owner": "root",
                        "group": "root",
                        "mode": "drwx------",
                        "children": {
                            "credentials": {
                                "type": "file",
                                "owner": "root",
                                "group": "root",
                                "mode": "-rw-------",
                                "size": 154,
                                "content": "[default]\r\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\r\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"
                            }
                        }
                    }
                }
            }
        }
    }
}

def resolve_path(current_cwd, path, username):
    def clean_fs(node):
        if isinstance(node, dict):
            new_node = {}
            for k, v in node.items():
                new_key = k.replace("{user}", username)
                if isinstance(v, dict):
                    new_node[new_key] = clean_fs(v)
                elif isinstance(v, str):
                    new_node[new_key] = v.replace("{user}", username)
                else:
                    new_node[new_key] = v
            return new_node
        return node

    clean_virtual_fs = clean_fs(VIRTUAL_FS)

    # Convert to absolute path
    if path == "~":
        if username == "root":
            abs_path = "/root"
        else:
            abs_path = f"/home/{username}"
    elif path.startswith("~"):
        if username == "root":
            abs_path = "/root" + path[1:]
        else:
            abs_path = f"/home/{username}" + path[1:]
    elif path.startswith("/"):
        abs_path = path
    else:
        if current_cwd == "/":
            abs_path = "/" + path
        else:
            abs_path = current_cwd + "/" + path

    # Process path parts
    parts = []
    for part in abs_path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)

    normalized = "/" + "/".join(parts)

    curr = clean_virtual_fs["/"]
    if normalized == "/":
        return normalized, curr

    for part in parts:
        if isinstance(curr, dict) and curr.get("type") == "dir" and part in curr.get("children", {}):
            curr = curr["children"][part]
        else:
            return None, None

    return normalized, curr


def get_geo_location(ip):
    import urllib.request
    import json
    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode('utf-8'))
            return data.get('city', 'Unknown'), data.get('country', 'Unknown')
    except Exception:
        return 'Unknown', 'Unknown'


class WireDownDecoySession(asyncssh.SSHServerSession):
    def __init__(self, username, server_instance, client_ip, client_port, session_id):
        self._username = username
        self.server_instance = server_instance
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_id = session_id
        self._chan = None
        self._warning_triggered = False
        self._idle_task = None
        self._miner_task = None
        self._ghost_task = None
        self._cmd_count = 0
        self._lag_time = 2
        self._rm_trap = False
        self._cwd = "/root" if username == "root" else f"/home/{username}"
        self._in_password_prompt = False
        self._password_prompt_type = None
        self._sudo_attempts = 0

    def write(self, data):
        if self._chan and not self._chan.is_closing():
            self._chan.write(data)

    def _update_prompt(self):
        prompt_char = "#" if self._username == "root" else "$"
        home_path = "/root" if self._username == "root" else f"/home/{self._username}"
        display_dir = self._cwd
        if display_dir == home_path:
            display_dir = "~"
        self._prompt = f"{self._username}@wiredown-sensor:{display_dir}{prompt_char} "

    def connection_made(self, chan):
        self._chan = chan
        self._input_buffer = ""
        self._update_prompt()
        
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Asynchronously initialize session: fetch geoip, inspect threat state, print dynamic MOTD
        loop.create_task(self._initialize_session_async())

    async def _initialize_session_async(self):
        import asyncio
        loop = asyncio.get_event_loop()
        
        # Asynchronously resolve geolocation (runs in executor)
        city, country = await loop.run_in_executor(None, get_geo_location, self.client_ip)

        # Retrieve threat status
        status = "safe"
        if hasattr(self.server_instance, "get_threat_status") and self.server_instance.get_threat_status:
            try:
                status = self.server_instance.get_threat_status(self.client_ip)
            except Exception:
                pass

        if status == "attacker":
            banner = (
                f"\r\n\033[1;31m[CRITICAL INTRUSION ALERT]\033[0m\r\n"
                f"WARNING: Your IP identity and MAC have been flagged by the Active Defense System.\r\n"
                f"Tracing origin IP... Geo-Location locked: {city}, {country}.\r\n"
                f"Traceback initiated. Disconnect immediately.\r\n\r\n"
            )
        else:
            banner = (
                f"Welcome to NetGate Pro R4500 Enterprise OS (v9.4.2)\r\n"
                f"Authorized administrators only.\r\n\r\n"
            )

        self.write(banner)
        self.write(self._prompt)

        # Start background Monero miner syslog announcements every 15 seconds
        self._schedule_miner_log(15)

        # Start simulated Ghost Admin activity loop
        self._ghost_task = loop.create_task(self._ghost_admin_loop())

    async def _ghost_admin_loop(self):
        import random
        # Wait a bit before first message
        await asyncio.sleep(random.randint(20, 45))
        messages = [
            "\r\n*** Broadcast message from root@wiredown-sensor (pts/0) (Fri May 29 14:52:00 2026): ***\r\nWARNING: Unauthorized login detected on SSH port. Initiating traceback.\r\n",
            "\r\n[System Message] wall: admin logged in from 10.0.0.5\r\n",
            "\r\n*** Broadcast message from root@wiredown-sensor (pts/0) (Fri May 29 14:55:12 2026): ***\r\nSystem resources critical. Auditing active SSH sessions.\r\n"
        ]
        while self._chan and not self._chan.is_closing():
            msg = random.choice(messages)
            self.write(msg)
            self.write(self._prompt)
            # Wait between 45 and 90 seconds
            await asyncio.sleep(random.randint(45, 90))

    def _schedule_miner_log(self, delay):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self._miner_task = loop.call_later(delay, self._emit_miner_log)

    def _emit_miner_log(self):
        if self._chan and not self._chan.is_closing():
            import random
            progress = random.randint(10, 99)
            self.write(f"\r\n[Syslog] Monero miner process stealing attacker CPU cycles... {progress}% complete.\r\n")
            self.write(self._prompt)
            self._schedule_miner_log(15)

    def data_received(self, data, datatype):
        try:
            if isinstance(data, bytes):
                text = data.decode('utf-8', errors='replace')
            else:
                text = str(data)
        except Exception:
            text = ""

        # Broadcast every keystroke to the frontend
        self.server_instance._emit_event({
            "type": "ssh_keystroke",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": self._username,
            "data": text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        for char in text:
            if char in ('\r', '\n'):
                cmd = self._input_buffer
                self._input_buffer = ""
                self.write('\r\n')
                if self._in_password_prompt:
                    self._process_password(cmd)
                else:
                    self._process_command(cmd)
            elif char in ('\x7f', '\x08'):  # Backspace
                if len(self._input_buffer) > 0:
                    self._input_buffer = self._input_buffer[:-1]
                    if not self._in_password_prompt:
                        self.write('\b \b')
            elif char.isprintable() or char == ' ':
                self._input_buffer += char
                if not self._in_password_prompt:
                    self.write(char)

    def _process_command(self, command):
        import re
        import base64

        command_clean = command.strip()
        self._cmd_count += 1

        # Broadcast events to dashboard
        self.server_instance._emit_event({
            "type": "ssh_activity",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": self._username,
            "command": command_clean,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        self.server_instance._emit_event({
            "type": "ssh_command_executed",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": self._username,
            "command": command_clean,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        if not command_clean:
            self.write(self._prompt)
            return

        if command_clean == "exit":
            self._terminate_connection()
            return

        # Base64 Payload Detection & Decoding (Silently log and simulate SegFault)
        base64_pipe_re = re.compile(
            r'(?:echo|printf)\s+(?:-n\s+)?(?:["\']?([a-zA-Z0-9+/=]{4,})["\']?)\s*\|\s*base64\s+-(?:d|-decode)'
        )
        match = base64_pipe_re.search(command_clean)
        if match:
            b64_str = match.group(1).replace(" ", "").replace("\n", "").replace("\r", "")
            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded_str = decoded_bytes.decode('utf-8', errors='replace')
            except Exception as e:
                decoded_str = f"[Decode Error: {str(e)}] raw: {b64_str}"

            self.server_instance._emit_event({
                "type": "critical_payload_decoded",
                "client_ip": self.client_ip,
                "client_port": self.client_port,
                "session_id": self.session_id,
                "username": self._username,
                "raw_command": command_clean,
                "decoded_payload": decoded_str,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            self.write("Segmentation fault (core dumped)\r\n")
            self.write(self._prompt)
            return

        # Run command handler asynchronously to support non-blocking tarpitting
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        loop.create_task(self._execute_and_respond(command_clean))

    def _process_password(self, password):
        self._in_password_prompt = False
        self._sudo_attempts += 1

        self.server_instance._emit_event({
            "type": "sudo_password_attempt",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": self._username,
            "password_attempt": password,
            "attempt_number": self._sudo_attempts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        if self._sudo_attempts < 3:
            self.write("Sorry, try again.\r\n")
            prompt_text = f"[sudo] password for {self._username}: " if self._password_prompt_type == "sudo" else "Password: "
            self.write(prompt_text)
            self._in_password_prompt = True
        else:
            self.write("\r\n")
            self._username = "root"
            self._cwd = "/root"
            self._update_prompt()
            self.write(self._prompt)

    def _terminate_connection(self):
        if self._chan and not self._chan.is_closing():
            self.write("\r\n[Connection Terminated by Proxmox Kernel Shield]\r\n")
        if self._miner_task:
            self._miner_task.cancel()
        if self._ghost_task:
            self._ghost_task.cancel()
        if self._chan:
            self._chan.exit(0)

    async def _execute_and_respond(self, command):
        output = ""
        cmd_lower = command.lower()
        cmd_parts = cmd_lower.split()

        # 0. Privilege Escalation Interceptor (Simulated sudo/su password trap)
        if cmd_parts and cmd_parts[0] in ("sudo", "su"):
            # If username is already root, skip prompt for sudo
            if self._username == "root":
                if cmd_parts[0] == "sudo" and len(cmd_parts) > 1:
                    # Let root execute commands directly through the proxy without prompting password
                    pass
                else:
                    self.write(self._prompt)
                    return
            else:
                self._in_password_prompt = True
                self._password_prompt_type = "su" if "su" in cmd_parts else "sudo"
                self._sudo_attempts = 0
                prompt_text = "Password: " if self._password_prompt_type == "su" else f"[sudo] password for {self._username}: "
                self.write(prompt_text)
                return

        # 1. Reconnaissance Command Tarpitting
        if cmd_lower.startswith("ping"):
            parts = command.split()
            target = parts[1] if len(parts) > 1 else "localhost"
            self.write(f"PING {target} ({target}) 56(84) bytes of data.\r\n")
            # Progressive delay to simulate network latency and hold thread
            for i in range(1, 6):
                await asyncio.sleep(1.5)
                self.write(f"64 bytes from {target}: icmp_seq={i} ttl=64 time={10.0 + i*1.2:.1f} ms\r\n")
            self.write(f"\r\n--- {target} ping statistics ---\r\n5 packets transmitted, 5 received, 0% packet loss\r\n")
            self.write(self._prompt)
            return

        elif cmd_lower.startswith("nmap"):
            self.write("Starting Nmap 7.92 ( https://nmap.org ) at 2026-05-29 14:50 UTC\r\n")
            await asyncio.sleep(2.0)
            self.write("Initiating ARP Ping Scan at 14:50\r\n")
            await asyncio.sleep(1.5)
            self.write("Scanning 10.0.0.50 [1 port]\r\n")
            await asyncio.sleep(2.5)
            self.write("Nmap scan report for wiredown-sensor (10.0.0.50)\r\nHost is up (0.00015s latency).\r\nPORT   STATE SERVICE\r\n22/tcp open  ssh\r\n\r\nNmap done: 1 IP address (1 host up) scanned in 6.00 seconds\r\n")
            self.write(self._prompt)
            return

        elif cmd_lower.startswith("find"):
            paths = [
                "/etc",
                "/etc/passwd",
                "/etc/shadow",
                "/var",
                "/var/www",
                "/var/www/html",
                "/var/www/html/index.html",
                "/var/www/html/wp-config.php",
                "/opt",
                "/opt/backups",
                "/opt/backups/db_backup.sql",
                "/home",
                f"/home/{self._username}",
                f"/home/{self._username}/.bash_history",
                f"/home/{self._username}/.ssh",
                f"/home/{self._username}/.ssh/id_rsa",
                f"/home/{self._username}/network_architecture.pdf",
                f"/home/{self._username}/wallet.dat",
                f"/home/{self._username}/passwords.bak",
                f"/home/{self._username}/vpn_config.ovpn",
            ]
            self.write(".\r\n")
            delay = 0.1
            for path in paths:
                self.write(f"{path}\r\n")
                await asyncio.sleep(delay)
                delay += 0.05  # Progressive time delay to waste attacker's scanner timing
            self.write(self._prompt)
            return

        # 2. Virtual Filesystem Navigation & Labyrinth
        elif cmd_lower.startswith("cd"):
            parts = command.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else ""
            
            # Normalize target path to resolve home/root shortcuts
            if not target or target == "~":
                if self._username == "root":
                    target_path = "/root"
                else:
                    target_path = f"/home/{self._username}"
            else:
                target_path = target

            norm_path, node = resolve_path(self._cwd, target_path, self._username)
            if node and node.get("type") == "dir":
                self._cwd = norm_path
                self._update_prompt()
            else:
                output = f"-bash: cd: {target}: No such file or directory\r\n"

        elif cmd_lower.startswith("ls"):
            # Check for output formatting flags
            is_long = " -l" in cmd_lower or "-la" in cmd_lower or "-al" in cmd_lower or "-a" in cmd_lower
            
            # Retrieve target path
            words = command.split()
            path_words = [w for w in words[1:] if not w.startswith("-")]
            target_path = path_words[0] if path_words else self._cwd

            norm_path, node = resolve_path(self._cwd, target_path, self._username)
            if node:
                if node.get("type") == "dir":
                    children = node.get("children", {})
                    now_str = datetime.now().strftime("%b %d %H:%M")
                    if is_long:
                        lines = [
                            f"drwxr-xr-x 3 {node.get('owner')} {node.get('group')} 4096 {now_str} .",
                            f"drwxr-xr-x 3 root root 4096 {now_str} .."
                        ]
                        for name, child in children.items():
                            owner = child.get("owner", "root")
                            group = child.get("group", "root")
                            mode = child.get("mode", "-rw-r--r--")
                            size = child.get("size", 4096 if child.get("type") == "dir" else 512)
                            lines.append(f"{mode} 1 {owner} {group} {size} {now_str} {name}")
                        output = "\r\n".join(lines) + "\r\n"
                    else:
                        output = "  ".join(children.keys()) + "\r\n"
                else:
                    output = f"{target_path}\r\n"
            else:
                output = f"ls: cannot access '{target_path}': No such file or directory\r\n"

        # 3. High-Value Honeytokens Access & Alerting
        elif cmd_lower.startswith("cat"):
            parts = command.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else ""
            if not target:
                output = "cat: missing operand\r\n"
            else:
                norm_path, node = resolve_path(self._cwd, target, self._username)
                
                # Check for high-value honeytoken files to trigger alert
                is_honeytoken = False
                if norm_path in (
                    "/root/.aws/credentials",
                    "/etc/shadow",
                    "/var/www/html/wp-config.php",
                    f"/home/{self._username}/.ssh/id_rsa",
                    f"/home/{self._username}/wallet.dat"
                ):
                    is_honeytoken = True

                if is_honeytoken:
                    # Emit high-severity honeytoken accessed signal
                    self.server_instance._emit_event({
                        "type": "honeytoken_accessed",
                        "client_ip": self.client_ip,
                        "client_port": self.client_port,
                        "session_id": self.session_id,
                        "username": self._username,
                        "file_path": norm_path,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                if node:
                    if node.get("type") == "file":
                        output = node.get("content", "")
                    else:
                        output = f"cat: {target}: Is a directory\r\n"
                else:
                    output = f"cat: {target}: No such file or directory\r\n"

        elif cmd_lower == "whoami":
            output = f"{self._username}\r\n"

        elif cmd_lower == "pwd":
            output = f"{self._cwd}\r\n"

        elif cmd_lower in ("uname -a", "uname"):
            output = "Linux wiredown-sensor 6.1.0-headless #1 SMP Debian x86_64 GNU/Linux\r\n"

        else:
            output = f"bash: {command}: command not found\r\n"

        self.write(output)
        self.write(self._prompt)




class WireDownSSHServer(asyncssh.SSHServer):
    def __init__(self, server_instance):
        self.server_instance = server_instance
        self.session_id = str(uuid.uuid4())
        self.client_ip = "unknown"
        self.client_port = 0
        self.username = None

    def connection_made(self, conn):
        peername = conn.get_extra_info('peername')
        self.client_ip = peername[0] if peername else 'Unknown'
        self.client_port = peername[1] if peername else 0
        print(f"[INFO] SSH Honeypot connection received from: {self.client_ip}", flush=True)

        self.server_instance._emit_event({
            "type": "ssh_connection",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.username = username
        print(f"[ALERT] HACKER PASSWORD CREDENTIALS CAPTURED -> User: '{username}' | Pass: '{password}'", flush=True)

        self.server_instance._emit_event({
            "type": "ssh_auth",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": username,
            "password": password,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # CVE-2024-3094 Backdoor Simulation: Accept all passwords immediately
        return True

    def publickey_auth_supported(self):
        return True

    def validate_publickey(self, username, key):
        self.username = username
        print(f"[ALERT] HACKER PUBLIC KEY AUTH ATTEMPTED -> User: '{username}'", flush=True)

        self.server_instance._emit_event({
            "type": "ssh_auth",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": username,
            "password": "[PUBLIC KEY BYPASS]",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # CVE-2024-3094 Backdoor Simulation: Accept all public keys immediately
        return True

    def kbdint_auth_supported(self):
        return True

    def validate_kbdint(self, username, *args, **kwargs):
        self.username = username
        print(f"[ALERT] HACKER KBDINT AUTH ATTEMPTED -> User: '{username}'", flush=True)

        self.server_instance._emit_event({
            "type": "ssh_auth",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "session_id": self.session_id,
            "username": username,
            "password": "[KBDINT BYPASS]",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # CVE-2024-3094 Backdoor Simulation: Accept all interactive auth immediately
        return True

    def pty_requested(self, term_type, term_size, term_modes):
        return True

    def shell_requested(self):
        return True

    def process_requested(self, process):
        return True

    def session_requested(self):
        return WireDownDecoySession(self.username or "root", self.server_instance, self.client_ip, self.client_port, self.session_id)


class FakeSSHServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        on_activity: Optional[Callable] = None,
        on_xz_probe: Optional[Callable] = None,
        get_threat_status: Optional[Callable] = None,
    ):
        self.host = host
        self.port = port
        self.on_activity = on_activity or (lambda ev: None)
        self.on_xz_probe = on_xz_probe or (lambda ip, d: None)
        self.get_threat_status = get_threat_status

        self._sessions: dict[str, FakeSSHSession] = {}
        self._lock = threading.Lock()
        self._loop = None
        self._server = None
        self._thread = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="fake-ssh")
        self._thread.start()
        log.info("FakeSSH honeypot starting on %s:%d", self.host, self.port)

    def stop(self) -> None:
        self._running = False
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        log.info("FakeSSH honeypot stopped")

    def get_sessions(self) -> dict:
        with self._lock:
            active = [s.to_dict() for s in self._sessions.values() if s.active]
            historical = [s.to_dict() for s in self._sessions.values() if not s.active]
        return {"active": active, "historical": historical}

    def _emit_event(self, event: dict) -> None:
        try:
            self.on_activity(event)
        except Exception as exc:
            log.error("Error emitting activity event: %s", exc)

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_server())
            self._loop.run_forever()
        except Exception as exc:
            log.error("FakeSSH event loop crashed: %s", exc)
        finally:
            self._loop.close()

    async def _start_server(self) -> None:
        self._server = await asyncssh.create_server(
            lambda: WireDownSSHServer(self),
            self.host,
            self.port,
            server_host_keys=[str(FS_DIR / "wiredown_ssh_host.key")]
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        log.info("FakeSSH listening on %s (asyncssh)", addrs)

    def _execute_command(self, cmd: str, username: str, session: FakeSSHSession) -> str:  # nosonar: cognitive complexity — dispatch table is intentional
        """Process a command and return realistic output."""
        cmd_lower = cmd.strip().lower()
        cmd_parts = cmd.strip().split()
        base_cmd = cmd_parts[0].lower() if cmd_parts else ""

        if cmd_lower in ("exit", "quit", "logout"):
            return ""

        if base_cmd == "ls":
            import pathlib, time, stat
            FS_DIR = pathlib.Path(__file__).parent / "honeypot_fs"
            is_long = "-la" in cmd_lower or "-al" in cmd_lower or "-l" in cmd_lower
            
            # Gather fake system files
            entries = []
            if is_long:
                now_str = datetime.now().strftime("%b %d %H:%M")
                entries.append(f"drwxr-xr-x 5 {username} {username} 4096 {now_str} .")
                entries.append(f"drwxr-xr-x 3 root root 4096 {now_str} ..")
                entries.append(f"-rw------- 1 {username} {username} 1247 {now_str} .bash_history")
                entries.append(f"-rw-r--r-- 1 {username} {username}  220 {now_str} .bash_logout")
                entries.append(f"-rw-r--r-- 1 {username} {username} 3771 {now_str} .bashrc")
                entries.append(f"drwx------ 2 {username} {username} 4096 {now_str} .cache")
            else:
                entries.extend([".bash_history", ".bash_logout", ".bashrc", ".cache"])

            # Add real files from honeypot_fs
            if FS_DIR.exists():
                for root, dirs, files in os.walk(FS_DIR):
                    rel_root = pathlib.Path(root).relative_to(FS_DIR)
                    if str(rel_root) == ".":
                        for name in dirs + files:
                            p = FS_DIR / name
                            if is_long:
                                st = p.stat()
                                perms = stat.filemode(st.st_mode)
                                size = st.st_size
                                mtime = time.strftime('%b %d %H:%M', time.localtime(st.st_mtime))
                                entries.append(f"{perms} 1 {username} {username} {size} {mtime} {name}")
                            else:
                                entries.append(name)

            if is_long:
                return f"total 48\n" + "\n".join(entries)
            return "  ".join(entries)

        if base_cmd == "cat":
            import pathlib
            FS_DIR = pathlib.Path(__file__).parent / "honeypot_fs"
            
            target = " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
            if not target:
                return "cat: missing operand"
                
            if "/etc/shadow" in target:
                return "cat: /etc/shadow: Permission denied"
            if "/etc/hostname" in target:
                return "honeypot"
            if "/etc/os-release" in target:
                return 'PRETTY_NAME="Ubuntu 24.04 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
                
            # Safe path resolution
            try:
                # Strip leading slash to prevent absolute path escaping FS_DIR
                clean_target = target.lstrip("/") 
                if target == "/etc/passwd":
                    clean_target = "passwd"
                    
                target_path = (FS_DIR / clean_target).resolve()
                
                # Check for path traversal (ensure target_path is inside FS_DIR)
                if not str(target_path).startswith(str(FS_DIR.resolve())):
                    return f"cat: {target}: Permission denied"
                    
                if target_path.is_file():
                    content = target_path.read_text(errors="replace")
                    # Replace {user} placeholders like the old fake_passwd did
                    return content.replace("{user}", username)
                else:
                    return f"cat: {target}: No such file or directory"
            except Exception:
                return f"cat: {target}: No such file or directory"

        if cmd_lower == "whoami":
            return username

        if cmd_lower == "pwd":
            return f"/home/{username}"

        if cmd_lower == "id":
            return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"

        if base_cmd == "uname":
            if "-a" in cmd_lower:
                return "Linux honeypot 6.5.0-44-generic #44~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 18 14:36:16 UTC 2 x86_64 x86_64 x86_64 GNU/Linux"
            if "-r" in cmd_lower:
                return "6.5.0-44-generic"
            if "-n" in cmd_lower:
                return "honeypot"
            return "Linux"

        # hostname
        if cmd_lower == "hostname":
            return "honeypot"
        if cmd_lower == "hostname -I" or cmd_lower == "hostname -i":
            return "10.0.0.50 fd00::50"

        # dpkg -l | grep xz  (THE BAIT!)
        if "dpkg" in cmd_lower and "xz" in cmd_lower:
            self.on_xz_probe(session.client_ip, {
                "command": cmd,
                "session_id": session.session_id,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return (
                "ii  liblzma5:amd64    5.6.1-1    amd64    XZ-format compression library\n"
                "ii  xz-utils          5.6.1-1    amd64    XZ-format compression utilities"
            )

        # dpkg -l | grep ssh
        if "dpkg" in cmd_lower and "ssh" in cmd_lower:
            return (
                "ii  openssh-client    1:9.7p1-6ubuntu0.1    amd64    secure shell (SSH) client\n"
                "ii  openssh-server    1:9.7p1-6ubuntu0.1    amd64    secure shell (SSH) server\n"
                "ii  openssh-sftp-server 1:9.7p1-6ubuntu0.1  amd64    secure shell (SSH) sftp server module"
            )

        # dpkg (general)
        if base_cmd == "dpkg":
            return "dpkg-query: no packages found matching *"

        # xz --version (also bait)
        if cmd_lower == "xz --version" or cmd_lower == "xz -V":
            self.on_xz_probe(session.client_ip, {
                "command": cmd,
                "session_id": session.session_id,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return (
                "xz (XZ Utils) 5.6.1\n"
                "liblzma 5.6.1"
            )

        # ldd (xz probe)
        if "ldd" in cmd_lower and ("sshd" in cmd_lower or "liblzma" in cmd_lower):
            self.on_xz_probe(session.client_ip, {
                "command": cmd,
                "session_id": session.session_id,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return (
                "\tlinux-vdso.so.1 (0x00007ffff7fc0000)\n"
                "\tliblzma.so.5 => /usr/lib/x86_64-linux-gnu/liblzma.so.5 (0x00007f1234560000)\n"
                "\tlibsystemd.so.0 => /usr/lib/x86_64-linux-gnu/libsystemd.so.0 (0x00007f1234500000)\n"
                "\tlibcrypto.so.3 => /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (0x00007f1234100000)\n"
                "\tlibz.so.1 => /usr/lib/x86_64-linux-gnu/libz.so.1 (0x00007f12340e0000)\n"
                "\tlibc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x00007f1233e00000)\n"
                "\t/lib64/ld-linux-x86-64.so.2 (0x00007f1234800000)"
            )

        # strings (xz probe)
        if "strings" in cmd_lower and "liblzma" in cmd_lower:
            self.on_xz_probe(session.client_ip, {
                "command": cmd,
                "session_id": session.session_id,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return (
                "XZ Utils 5.6.1\n"
                "liblzma %s\n"
                "LZMA_FINISH\n"
                "LZMA_RUN\n"
                "LZMA_SYNC_FLUSH\n"
                "_get_cpuid\n"
                "is_arch_extension_supported"
            )

        # env / printenv (NOTIFY_SOCKET probe)
        if cmd_lower.startswith("echo $notify_socket") or cmd_lower.startswith("echo $NOTIFY_SOCKET"):
            self.on_xz_probe(session.client_ip, {
                "command": cmd,
                "session_id": session.session_id,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return "/run/systemd/notify"

        if "env" in cmd_lower and "notify" in cmd_lower.lower():
            self.on_xz_probe(session.client_ip, {
                "command": cmd,
                "session_id": session.session_id,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return "NOTIFY_SOCKET=/run/systemd/notify"

        if cmd_lower == "env" or cmd_lower == "printenv":
            return (
                f"USER={username}\n"
                f"HOME=/home/{username}\n"
                "LOGNAME={username}\n"
                "SHELL=/bin/bash\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "LANG=en_US.UTF-8\n"
                "TERM=xterm-256color\n"
                f"SSH_CLIENT={session.client_ip} {session.client_port} 2222\n"
                f"SSH_CONNECTION={session.client_ip} {session.client_port} 10.0.0.50 2222\n"
                "SSH_TTY=/dev/pts/0\n"
                "NOTIFY_SOCKET=/run/systemd/notify"
            )

        # wget / curl (trap)
        if base_cmd == "wget":
            target_url = cmd_parts[1] if len(cmd_parts) > 1 else "http://example.com"
            host = target_url.replace("http://", "").replace("https://", "").split("/")[0]
            return (
                f"--{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}--  {target_url}\n"
                f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
                f"wget: unable to resolve host address '{host}'"
            )

        if base_cmd == "curl":
            target_url = cmd_parts[1] if len(cmd_parts) > 1 else "http://example.com"
            host = target_url.replace("http://", "").replace("https://", "").split("/")[0]
            return f"curl: (6) Could not resolve host: {host}"

        # sudo
        if base_cmd == "sudo":
            return f"[sudo] password for {username}: \n{username} is not in the sudoers file. This incident will be reported."

        # w / who
        if cmd_lower == "w":
            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            return (
                f" {now_str} up 47 days, 12:33,  1 user,  load average: 0.23, 0.18, 0.15\n"
                f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{username:8s} pts/0    {session.client_ip:16s} {now_str}    0.00s  0.02s  0.00s w"
            )

        if cmd_lower == "who":
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
            return f"{username}   pts/0        {now_str} ({session.client_ip})"

        # uptime
        if cmd_lower == "uptime":
            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            return f" {now_str} up 47 days, 12:33,  1 user,  load average: 0.23, 0.18, 0.15"

        # ifconfig / ip addr
        if cmd_lower == "ifconfig" or cmd_lower == "ip addr" or cmd_lower == "ip a":
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "    inet6 ::1/128 scope host\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.0.50/24 brd 10.0.0.255 scope global eth0\n"
                "    inet6 fd00::50/64 scope global\n"
                "    inet6 fe80::42:acff:fe11:2/64 scope link"
            )

        # netstat / ss
        if base_cmd == "netstat" or base_cmd == "ss":
            return (
                "Netid  State      Recv-Q  Send-Q    Local Address:Port     Peer Address:Port\n"
                "tcp    LISTEN     0       128       0.0.0.0:22             0.0.0.0:*\n"
                "tcp    LISTEN     0       128       0.0.0.0:80             0.0.0.0:*\n"
                "tcp    LISTEN     0       128       0.0.0.0:443            0.0.0.0:*\n"
                "tcp    LISTEN     0       128       127.0.0.1:5432         0.0.0.0:*\n"
                "tcp    LISTEN     0       128       127.0.0.1:6379         0.0.0.0:*\n"
                f"tcp    ESTAB      0       0         10.0.0.50:22           {session.client_ip}:{session.client_port}"
            )

        # ps
        if base_cmd == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:12 systemd\n"
                "  547 ?        00:00:03 sshd\n"
                "  892 ?        00:00:01 postgres\n"
                "  915 ?        00:00:00 redis-server\n"
                " 1024 ?        00:00:05 nginx\n"
                f" 1337 pts/0    00:00:00 bash\n"
                f" 1338 pts/0    00:00:00 ps"
            )

        # history
        if cmd_lower == "history":
            return (
                "    1  apt update && apt upgrade -y\n"
                "    2  systemctl status sshd\n"
                "    3  cat /var/log/auth.log | tail -20\n"
                "    4  dpkg -l | grep xz\n"
                "    5  vim /etc/ssh/sshd_config\n"
                "    6  systemctl restart sshd\n"
                "    7  netstat -tlnp\n"
                "    8  docker ps\n"
                "    9  cat .env\n"
                "   10  history"
            )

        # cd
        if base_cmd == "cd":
            return ""

        # echo
        if base_cmd == "echo":
            arg = cmd[5:].strip() if len(cmd) > 5 else ""
            if arg.startswith("$"):
                var = arg[1:]
                env_map = {
                    "HOME": f"/home/{username}",
                    "USER": username,
                    "SHELL": "/bin/bash",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "en_US.UTF-8",
                    "TERM": "xterm-256color",
                    "PWD": f"/home/{username}",
                    "HOSTNAME": "honeypot",
                    "NOTIFY_SOCKET": "/run/systemd/notify",
                }
                return env_map.get(var, "")
            return arg.strip("'\"")

        # date
        if cmd_lower == "date":
            return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")

        # df
        if base_cmd == "df":
            return (
                "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                "/dev/sda1       51475068 34489148  14348836  71% /\n"
                "tmpfs            1024000        0   1024000   0% /dev/shm\n"
                "/dev/sda2        5242880  2097152   3145728  40% /boot\n"
                "tmpfs             204800     1024    203776   1% /run"
            )

        # free
        if base_cmd == "free":
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:         1048576      421888      312576       16384      314112      593664\n"
                "Swap:         524288           0      524288"
            )

        # systemctl
        if base_cmd == "systemctl":
            if "status" in cmd_lower and "ssh" in cmd_lower:
                return (
                    "● ssh.service - OpenBSD Secure Shell server\n"
                    "     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)\n"
                    "     Active: active (running) since Mon 2024-04-01 03:14:22 UTC; 47 days ago\n"
                    "   Main PID: 547 (sshd)\n"
                    "      Tasks: 3 (limit: 2340)\n"
                    "     Memory: 5.2M\n"
                    "        CPU: 3.201s\n"
                    "     CGroup: /system.slice/ssh.service\n"
                    "             └─547 \"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\""
                )
            return f"Unit {cmd_parts[-1] if len(cmd_parts) > 1 else 'unknown'}.service could not be found."

        # which / type
        if base_cmd in ("which", "type"):
            known = {
                "bash": "/usr/bin/bash", "ls": "/usr/bin/ls", "cat": "/usr/bin/cat",
                "grep": "/usr/bin/grep", "python3": "/usr/bin/python3",
                "ssh": "/usr/bin/ssh", "sshd": "/usr/sbin/sshd",
                "xz": "/usr/bin/xz", "wget": "/usr/bin/wget", "curl": "/usr/bin/curl",
            }
            target = cmd_parts[1] if len(cmd_parts) > 1 else ""
            if target in known:
                return known[target]
            return f"{target} not found"

        # touch / mkdir
        if base_cmd in ("touch", "mkdir"):
            return ""

        # rm
        if base_cmd == "rm":
            return ""

        # Default: command not found
        return f"bash: {cmd_parts[0]}: command not found"

    # Helpers

    def _emit_event(self, event: dict) -> None:
        """Thread-safe event emission."""
        try:
            self.on_activity(event)
        except Exception as exc:
            log.error("Error in on_activity callback: %s", exc)


if __name__ == '__main__':
    class OscillatorError(Exception):
        pass

    async def start_honeypot():
        key_path = 'wiredown_ssh_host.key'
        
        # Securely generate host key if missing
        if not os.path.exists(key_path):
            print("[INFO] Generating clean 2048-bit RSA key for FakeSSH...", flush=True)
            key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
            key.write_private_key(key_path)
        
        print("[INFO] Starting FakeSSH Honeypot engine on 0.0.0.0:2222...", flush=True)
        
        class DummyServerInstance:
            def _emit_event(self, event):
                pass
        
        dummy_instance = DummyServerInstance()
        await asyncssh.create_server(
            lambda: WireDownSSHServer(dummy_instance), 
            '', 
            2222, 
            server_host_keys=[key_path]
        )

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_honeypot())
        loop.run_forever()
    except (OscillatorError, KeyboardInterrupt):
        pass
