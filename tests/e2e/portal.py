#!/usr/bin/env python3
"""End to end test of the compose stack: Keycloak sign in, enrolment, tunnel, revocation.

Uses a throwaway compose project and removes it (volumes included) afterwards.
Needs Docker, ports 8480, 8081, 500/udp and 4500/udp free, and the ripsec-strongswan
image built by tests/interop/run.sh.
"""

import html
import http.cookiejar
import json
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
PORTAL = "http://localhost:8480"
PROJECT = "ripsec-e2e"
CLIENT = "ripsec-e2e-client"
failures = 0


def check(what, ok, detail=""):
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {what}" + ("" if ok else f"  {str(detail)[-1500:]}"), flush=True)
    failures += 0 if ok else 1


def run(*args, input=None):
    return subprocess.run(args, input=input, capture_output=True, text=True, encoding="utf-8", errors="replace")


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method, url, data=None, headers=None):
        request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            # Longer than the 20 s the portal may wait for Cloud Cache before answering.
            response = self.opener.open(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        for cookie in self.jar:  # browsers treat localhost as a secure context
            cookie.secure = False
        return response.status, response.read().decode(), response.geturl()

    def api(self, method, path, body=None, headers=None):
        headers = {"x-ripsec": "1"} if headers is None else headers
        if body is not None:
            headers = {**headers, "content-type": "application/json"}
            body = json.dumps(body).encode()
        status, text, _ = self.request(method, PORTAL + path, body, headers)
        return status, json.loads(text) if text[:1] in ("{", "[") else text

    def sign_in(self, user, new_password):
        _, page, _ = self.request("GET", PORTAL + "/auth/login")
        password = "change-me"
        for _ in range(3):
            action = re.search(r'<form[^>]*action="([^"]+)"', page)
            if not action:
                return
            if "password-new" in page:
                fields = {"password-new": new_password, "password-confirm": new_password}
            else:
                fields = {"username": user, "password": password}
            _, page, _ = self.request("POST", html.unescape(action[1]), urllib.parse.urlencode(fields).encode())


def wait_for(description, probe, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if probe():
                return True
        except (OSError, ValueError):
            pass
        time.sleep(1)
    check(description, False, "timed out")
    return False


def main(env_file):
    compose = ["docker", "compose", "-p", PROJECT, "--env-file", env_file, "-f", str(ROOT / "deploy" / "compose.yaml")]
    up = run(*compose, "up", "-d", "--build")
    if up.returncode:
        check("compose up", False, up.stderr)
        return
    realm = "http://localhost:8081/realms/ripsec/.well-known/openid-configuration"
    if not wait_for("Keycloak ready", lambda: urllib.request.urlopen(realm, timeout=3).status == 200, 240):
        return

    anonymous = Browser()
    check("API requires sign in", anonymous.api("GET", "/api/devices")[0] == 401)
    check("writes require the CSRF header", anonymous.api("POST", "/api/devices", {"name": "x"}, {})[0] == 403)
    check("forged callback is refused", anonymous.request("GET", PORTAL + "/auth/callback?code=a&state=b")[0] == 400)

    alice, bob = Browser(), Browser()
    alice.sign_in("alice", secrets.token_urlsafe(18))
    bob.sign_in("bob", secrets.token_urlsafe(18))
    status, me = alice.api("GET", "/api/me")
    check("admin signs in through Keycloak", status == 200 and me["admin"] is True, me)
    status, me = bob.api("GET", "/api/me")
    check("user signs in and is not an admin", status == 200 and me["admin"] is False, me)

    status, _ = bob.api("POST", "/api/devices", {"name": "net", "remote_subnets": ["192.168.7.0/24"]})
    check("users cannot add sites", status == 403, status)
    status, site = alice.api("POST", "/api/devices", {"name": "branch", "remote_subnets": ["192.168.7.0/24"]})
    check("admin can add a site", status == 200, site)
    status, laptop = bob.api("POST", "/api/devices", {"name": "<b>laptop</b>"})
    check("user enrols a device", status == 200, laptop)
    check("Apple profile is escaped and post-quantum",
          "&lt;b&gt;laptop" in laptop["apple"] and "PostQuantumKeyExchangeMethods" in laptop["apple"])
    check("users only see their own devices", len(bob.api("GET", "/api/devices")[1]) == 1)
    check("admins see all devices", len(alice.api("GET", "/api/devices")[1]) == 2)
    check("listing never includes secrets", "secret" not in json.dumps(alice.api("GET", "/api/devices")[1]))
    status, _ = bob.api("DELETE", f"/api/devices/{urllib.parse.quote(site['device']['id'])}")
    check("users cannot revoke others' devices", status == 404, status)

    # Connect with the generated strongSwan configuration, as downloaded.
    config = laptop["strongswan"].replace("remote_addrs = 127.0.0.1", "remote_addrs = ripsec")
    run("docker", "run", "-d", "--name", CLIENT, "--network", f"{PROJECT}_default", "--cap-add", "NET_ADMIN",
        "ripsec-strongswan", "/usr/libexec/ipsec/charon")
    run("docker", "exec", "-i", CLIENT, "sh", "-c", "cat > /etc/swanctl/swanctl.conf", input=config)
    wait_for("charon ready", lambda: run("docker", "exec", CLIENT, "swanctl", "--stats").returncode == 0, 20)
    run("docker", "exec", CLIENT, "swanctl", "--load-all")
    result = run("docker", "exec", CLIENT, "swanctl", "--initiate", "--child", "net", "--timeout", "15")
    check("tunnel from the generated config", result.returncode == 0, result.stdout + result.stderr)
    keycloak = run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                   f"{PROJECT}-keycloak-1").stdout.strip()
    ping = run("docker", "exec", CLIENT, "ping", "-c", "3", "-W", "2", keycloak)
    diagnostics = ""
    if ping.returncode:
        diagnostics = run("docker", "exec", CLIENT, "ip", "route", "get", keycloak).stdout + run(
            "docker", "exec", f"{PROJECT}-ripsec-1", "sh", "-c",
            "iptables -t nat -vnL POSTROUTING; ip xfrm policy; grep -v ' 0$' /proc/net/xfrm_stat").stdout
    check("traffic is forwarded through the gateway", ping.returncode == 0,
          f"target={keycloak!r} {ping.stdout} {ping.stderr} {diagnostics}")
    sessions = bob.api("GET", "/api/sessions")[1]
    check("portal shows a post-quantum session with traffic",
          len(sessions) == 1 and sessions[0]["post_quantum"] and sessions[0]["bytes_in"] > 0, sessions)

    status, _ = bob.api("DELETE", f"/api/devices/{urllib.parse.quote(laptop['device']['id'])}")
    check("user revokes the device", status == 204, status)
    time.sleep(3)
    check("session is dropped", alice.api("GET", "/api/sessions")[1] == [])
    sas = run("docker", "exec", CLIENT, "swanctl", "--list-sas").stdout
    check("client was told to disconnect", "ESTABLISHED" not in sas, sas)
    result = run("docker", "exec", CLIENT, "swanctl", "--initiate", "--child", "net", "--timeout", "10")
    check("revoked credential cannot reconnect", result.returncode != 0, result.stdout)

    status, _ = bob.api("POST", "/auth/logout")
    check("sign out ends the portal session", status == 200 and bob.api("GET", "/api/me")[0] == 401)
    log = run(*compose, "logs", "ripsec").stdout
    print(log[-1500:])
    check("NAT rule was installed", "could not add the NAT rule" not in log)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        env_file = pathlib.Path(directory, "env")
        env_file.write_text(f"KEYCLOAK_ADMIN_PASSWORD={secrets.token_urlsafe(18)}\n")
        try:
            main(str(env_file))
            if failures:
                print(run("docker", "compose", "-p", PROJECT, "--env-file", str(env_file), "-f",
                          str(ROOT / "deploy" / "compose.yaml"), "logs", "--tail", "30", "ripsec").stdout)
        finally:
            run("docker", "rm", "-f", CLIENT)
            run("docker", "compose", "-p", PROJECT, "--env-file", str(env_file), "-f",
                str(ROOT / "deploy" / "compose.yaml"), "down", "-v", "--remove-orphans")
    print("all checks passed" if not failures else f"{failures} check(s) failed")
    sys.exit(1 if failures else 0)
