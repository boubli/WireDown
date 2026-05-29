# Fake SSH Honeypot Server
# Drops bots into a plain-text interactive shell that logs keystrokes.

import asyncio
import asyncssh
import logging
import os
import struct
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


class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, server_instance, session_model):
        self.server_instance = server_instance
        self.session_model = session_model
        self.username = self.session_model.username or "root"
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan
        welcome_msg = (
            "\r\n"
            "══════════════════════════════════════════\r\n"
            "  Ubuntu 24.04 LTS (GNU/Linux 6.5.0-44)\r\n"
            "══════════════════════════════════════════\r\n"
            "\r\n"
            "  System information as of "
        ) + datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + (
            "\r\n\r\n"
            "  System load:  0.23              Users logged in: 1\r\n"
            "  Memory usage: 42%               IPv4 address:    10.0.0.50\r\n"
            "  Swap usage:   0%                IPv6 address:    ::1\r\n"
            "  Disk usage:   67%               Processes:       187\r\n"
            "\r\n"
            "  * Security update: xz-utils 5.6.1 available.\r\n"
            "    Run `sudo apt upgrade` to update.\r\n"
            "\r\n"
            "Last login: "
        ) + datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y") + " from 192.168.1.105\r\n"
        self._chan.write(welcome_msg)
        self._prompt()

    def _prompt(self):
        self._chan.write(f"{self.username}@honeypot:~$ ")

    def data_received(self, data, datatype):
        line = data.strip()
        
        # handle enter without data
        if not line:
            self._chan.write("\r\n")
            self._prompt()
            return
            
        cmd = line
        output = self.server_instance._execute_command(cmd, self.username, self.session_model)
        
        cmd_event = {
            "type": "ssh_command",
            "client_ip": self.session_model.client_ip,
            "client_port": self.session_model.client_port,
            "session_id": self.session_model.session_id,
            "username": self.username,
            "password": self.session_model.password,
            "command": cmd,
            "output": output,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.session_model.commands.append(cmd_event)
        self.server_instance._emit_event(cmd_event)

        if cmd in ("exit", "quit", "logout"):
            self._chan.write("\r\nlogout\r\nConnection to honeypot closed.\r\n")
            self._chan.exit(0)
            return

        self._chan.write("\r\n" + output + "\r\n")
        self._prompt()
        
    def eof_received(self):
        self._chan.exit(0)


class FakeSSHServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        on_activity: Optional[Callable] = None,
        on_xz_probe: Optional[Callable] = None,
    ):
        self.host = host
        self.port = port
        self.on_activity = on_activity or (lambda ev: None)
        self.on_xz_probe = on_xz_probe or (lambda ip, d: None)

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
        class ServerFactory(asyncssh.SSHServer):
            def __init__(self, server_instance):
                self.server_instance = server_instance
                self.session_id = str(uuid.uuid4())
                self.client_ip = "unknown"
                self.client_port = 0
                self.username = "root"
                self.password = None
                
            def connection_made(self, conn):
                peer = conn.get_extra_info('peername')
                self.client_ip = peer[0] if peer else "unknown"
                self.client_port = peer[1] if peer else 0
                
                self.server_instance._emit_event({
                    "type": "ssh_connection",
                    "client_ip": self.client_ip,
                    "client_port": self.client_port,
                    "session_id": self.session_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                log.info("SSH connection from %s:%d [%s]", self.client_ip, self.client_port, self.session_id)
                
            def connection_lost(self, exc):
                log.info("Client %s disconnected", self.client_ip)
                
            def begin_auth(self, username):
                # Return False to require authentication (forces password prompt)
                self.username = username
                return False
                
            def password_auth_supported(self):
                return True
                
            def validate_password(self, username, password):
                self.username = username
                self.password = password
                
                self.server_instance._emit_event({
                    "type": "ssh_auth",
                    "client_ip": self.client_ip,
                    "client_port": self.client_port,
                    "session_id": self.session_id,
                    "username": username,
                    "password": password,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                log.warning("[ALERT] SSH Login Attempt captured -> User: %s | Pass: %s", username, password)
                
                # Return True to drop them into the interactive fake shell
                return True

            def session_requested(self):
                session_model = FakeSSHSession(self.session_id, self.client_ip, self.client_port)
                session_model.username = self.username
                session_model.password = self.password
                with self.server_instance._lock:
                    self.server_instance._sessions[self.session_id] = session_model
                return HoneypotSession(self.server_instance, session_model)

        self._server = await asyncssh.create_server(
            lambda: ServerFactory(self),
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
