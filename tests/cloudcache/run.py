#!/usr/bin/env python3
"""End to end test of Cloud Cache mode against a real three node Cloud Cache cluster.

    python tests/cloudcache/run.py /path/to/cloud-cache

Starts a throwaway copy of that checkout's compose stack (project `ripsec-kv`) with TLS added,
and removes it, volumes included, afterwards. The checkout is only read.
Needs Docker, ports 8480, 18080, 18081, 17379 and 18404 free, and the ripsec-strongswan image
built by tests/interop/run.sh.
"""

import json
import os
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

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tests" / "e2e"))
sys.dont_write_bytecode = True
from portal import Browser, check, run, wait_for  # noqa: E402
import portal  # noqa: E402

PROJECT = "ripsec-kv"
CLIENT = "ripsec-kv-client"
KEYCLOAK = "http://localhost:18081"
KV = "http://localhost:18080"
NODES = ["kv1", "kv2", "kv3"]
PREFIX = "ripsec:vpn.ripsec.test:"

CERTIFICATES = """
set -e
cd /tls
ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
openssl req -x509 $ec -days 2 -subj "/CN=test CA" -keyout ca.key -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
issue() {
  openssl req $ec -subj "/CN=$1" -keyout $1.key -out $1.csr 2>/dev/null
  printf 'subjectAltName=DNS:%s\\nextendedKeyUsage=serverAuth\\n' "$2" > $1.ext
  openssl x509 -req -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile $1.ext -out $1.crt 2>/dev/null
}
issue kv kv.ripsec.test
issue keycloak keycloak
rm ca.key
chmod 755 . && chmod 644 *
"""


def config(organization=None):
    text = (ROOT / "deploy" / "ripsec.compose.toml").read_text()
    text = text.replace("localhost:8081", "localhost:18081")
    if organization:
        text += f"""
[cloud_cache]
address = "kv.ripsec.test:7379"
ca_file = "/etc/ripsec/ca.crt"
token_url = "https://keycloak:8443/realms/kv/protocol/openid-connect/token"
token_ca_file = "/etc/ripsec/ca.crt"
organization_id = "{organization}"
refresh_seconds = 5
"""
    return text


class Stack:
    def __init__(self, cloud_cache, directory, secret):
        self.directory = directory
        self.secret = secret
        env = directory / "env"
        env.write_text(
            f"TEST_DIR={directory.as_posix()}\nRIPSEC_ROOT={ROOT.as_posix()}\n"
            f"RIPSEC_GATEWAY_SECRET={secret}\n"
        )
        self.base = [
            "docker", "compose", "-p", PROJECT, "--env-file", str(env),
            "-f", str(cloud_cache / "deploy" / "docker-compose.yml"),
            "-f", str(HERE / "compose.override.yaml"),
        ]

    def compose(self, *args):
        return run(*self.base, *args)

    def must(self, *args):
        result = self.compose(*args)
        if result.returncode:
            raise RuntimeError(f"compose {' '.join(args)}: {result.stderr[-3000:]}")
        return result

    def node(self, action, *names):
        run("docker", action, *[f"{PROJECT}-{name}-1" for name in names])

    def log(self):
        result = self.compose("logs", "--no-log-prefix", "ripsec")
        return result.stdout + result.stderr

    def restart_ripsec(self, *users):
        self.must("restart", "ripsec")
        portal_up()
        for user in users:  # Keycloak still knows them, so this needs no password
            user.sign_in("", "")

    def stored(self):
        """devices.json as it is on disk."""
        return self.compose("exec", "-T", "ripsec", "cat", "/var/lib/ripsec/devices.json").stdout


class Cache:
    """Reads and tampers with Cloud Cache through its HTTP API, as the gateway client."""

    def __init__(self, secret):
        self.secret = secret

    def call(self, method, path, data=None):
        form = {"grant_type": "client_credentials", "client_id": "ripsec-gateway",
                "client_secret": self.secret}
        with urllib.request.urlopen(f"{KEYCLOAK}/realms/kv/protocol/openid-connect/token",
                                    urllib.parse.urlencode(form).encode(), timeout=20) as response:
            token = json.load(response)["access_token"]
        request = urllib.request.Request(KV + path, data=data, method=method,
                                         headers={"authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    def path(self, device):
        return "/v1/kv/" + urllib.parse.quote(PREFIX + device, safe="")

    def get(self, device):
        status, body = self.call("GET", self.path(device))
        return body if status == 200 else None

    def put(self, device, value):
        return self.call("PUT", self.path(device), value.encode())[0]

    def devices(self):
        status, body = self.call("GET", "/v1/kv")
        return set(re.findall(re.escape(PREFIX) + r"([0-9a-f]+@ripsec)", body)) if status == 200 else None


def http_ok(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status == 200


def portal_up():
    return wait_for("portal listening",
                    lambda: Browser().api("GET", "/api/me")[0] == 401, 60)


def eventually(probe, seconds):
    deadline = time.time() + seconds
    while True:
        try:
            if probe():
                return True
        except (OSError, ValueError):
            pass
        if time.time() > deadline:
            return False
        time.sleep(2)


def connect(device):
    """Replaces any tunnel with a new one for this device."""
    profile = device["strongswan"].replace("remote_addrs = 127.0.0.1", "remote_addrs = ripsec")
    run("docker", "exec", CLIENT, "swanctl", "--terminate", "--ike", "ripsec", "--force")
    run("docker", "exec", "-i", CLIENT, "sh", "-c", "cat > /etc/swanctl/swanctl.conf", input=profile)
    run("docker", "exec", CLIENT, "swanctl", "--load-all", "--clear")
    return run("docker", "exec", CLIENT, "swanctl", "--initiate", "--child", "net",
               "--timeout", "10").returncode == 0


def enrol(user, name):
    status, body = user.api("POST", "/api/devices", {"name": name})
    return status, body, body["device"]["id"] if status == 200 else None


def scenario(stack, cache, organization):
    alice, bob = Browser(), Browser()
    alice.sign_in("alice", secrets.token_urlsafe(18))
    bob.sign_in("bob", secrets.token_urlsafe(18))

    print("== moving local secrets to Cloud Cache")
    status, laptop, laptop_id = enrol(bob, "laptop")
    check("device enrolled in local mode", status == 200, laptop)
    check("local file holds only a sealed secret",
          '"sealed"' in stack.stored() and '"secret"' not in stack.stored(), stack.stored())
    (stack.directory / "ripsec.toml").write_text(config(organization))
    stack.restart_ripsec(alice, bob)
    check("the secret is moved to Cloud Cache",
          eventually(lambda: (cache.get(laptop_id) or "").startswith("v1:"), 60), stack.log())
    check("and no longer kept locally",
          eventually(lambda: '"sealed"' not in stack.stored() and '"remote": true' in stack.stored(), 20),
          stack.stored())
    check("moved device still connects", connect(laptop), stack.log())

    print("== normal operation")
    status, phone, phone_id = enrol(bob, "phone")
    check("enrolment stores the secret", status == 200 and (cache.get(phone_id) or "").startswith("v1:"), phone)
    secret = re.search(r'secret = "?([^"\s]+)', phone["strongswan"])
    check("Cloud Cache never sees the plaintext secret",
          bool(secret) and secret[1] not in (cache.get(phone_id) or ""))
    check("new device connects", connect(phone), stack.log())
    stack.restart_ripsec(alice, bob)
    check("secrets are read back after a restart", eventually(lambda: connect(phone), 60), stack.log())

    print("== one node down")
    for name in NODES:
        stack.node("stop", name)
        status, body, device = enrol(alice, f"during-{name}")
        check(f"enrolment works without {name}", status == 200, f"{status} {body}\n{stack.log()}")
        if device:
            status, _ = alice.api("DELETE", f"/api/devices/{urllib.parse.quote(device)}")
            check(f"revocation works without {name}", status == 204, status)
        stack.node("start", name)
        wait_for(f"{name} ready again", lambda: http_ok(KV + "/readyz"), 60)
        time.sleep(8)

    print("== majority down")
    check("tunnel up before the outage", connect(phone), stack.log())
    stack.node("stop", "kv1", "kv2")
    status, body, _ = enrol(alice, "no-quorum")
    check("enrolment fails without a majority", status >= 500, f"{status} {body}")
    check("existing credentials keep working", connect(laptop), stack.log())
    status, _ = bob.api("DELETE", f"/api/devices/{urllib.parse.quote(laptop_id)}")
    check("revocation is accepted during the outage", status == 204, status)
    check("revoked device is refused at once", not connect(laptop))
    check("the pending delete is saved to disk", laptop_id in stack.compose(
        "exec", "-T", "ripsec", "cat", "/var/lib/ripsec/revocations.json").stdout)
    stack.restart_ripsec(alice, bob)
    stack.node("start", "kv1", "kv2")
    wait_for("cluster ready again", lambda: http_ok(KV + "/readyz"), 90)
    check("the delete is carried out after the outage and a restart",
          eventually(lambda: cache.get(laptop_id) is None, 120), stack.log())
    check("and then forgotten", eventually(lambda: laptop_id not in stack.compose(
        "exec", "-T", "ripsec", "cat", "/var/lib/ripsec/revocations.json").stdout, 60), stack.log())
    check("the failed enrolment leaves nothing behind",
          eventually(lambda: cache.devices() == {phone_id}, 90), f"{cache.devices()} want {phone_id}")
    check("the failed enrolment is not listed", len(alice.api("GET", "/api/devices")[1]) == 1,
          alice.api("GET", "/api/devices")[1])

    print("== Cloud Cache unreachable at startup")
    stack.must("stop", "haproxy")
    stack.restart_ripsec(alice, bob)
    check("nobody can connect without secrets", not connect(phone))
    stack.must("start", "haproxy")
    check("recovers by itself", eventually(lambda: connect(phone), 90), stack.log())

    print("== tampered entries")
    status, tablet, tablet_id = enrol(bob, "tablet")
    check("second device enrolled", status == 200, tablet)
    check("write succeeds", cache.put(tablet_id, cache.get(phone_id)) in (200, 201, 204))
    check("another device's entry is rejected as an incident",
          eventually(lambda: f"INCIDENT: the entry for {tablet_id}" in stack.log(), 30), stack.log())
    check("the tampered device is disabled", not connect(tablet))
    check("other devices are unaffected", connect(phone), stack.log())
    check("delete succeeds", cache.call("DELETE", cache.path(phone_id))[0] in (200, 204))
    check("a deleted entry disables its device",
          eventually(lambda: f"no secret for {phone_id}" in stack.log(), 30), stack.log())
    check("and it cannot connect", not connect(phone))


def main(cloud_cache):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
        directory = pathlib.Path(temporary).resolve()
        (directory / "tls").mkdir()
        result = run("docker", "run", "--rm", "-v", f"{(directory / 'tls').as_posix()}:/tls",
                     "rust:trixie", "sh", "-c", CERTIFICATES)
        if result.returncode:
            check("test certificates", False, result.stderr)
            return
        (directory / "ripsec.toml").write_text(config())
        os.environ.setdefault("CC_KEYCLOAK_PORT", "18081")
        secret = secrets.token_urlsafe(48)
        stack = Stack(cloud_cache, directory, secret)
        try:
            stack.must("up", "-d", "--build", "keycloak", "cluster-certs", *NODES, "haproxy")
            discovery = "/.well-known/openid-configuration"
            for realm in ("kv", "ripsec"):
                if not wait_for(f"Keycloak realm {realm}",
                                lambda: http_ok(f"{KEYCLOAK}/realms/{realm}{discovery}"), 300):
                    return
            if not wait_for("cluster ready", lambda: http_ok(KV + "/readyz"), 120):
                return
            os.environ.update(KEYCLOAK_URL=KEYCLOAK, KEYCLOAK_ADMIN_USER="admin",
                              KEYCLOAK_ADMIN_PASSWORD="admin", RIPSEC_GATEWAY_SECRET=secret)
            result = run(sys.executable, "-B", str(cloud_cache / "scripts" / "ripsec-gateway.py"))
            organization = re.search(r"organization ID: (\S+)", result.stdout)
            check("gateway client created", bool(organization), result.stdout + result.stderr)
            if not organization:
                return
            stack.must("up", "-d", "--build", "--no-deps", "ripsec")
            if not portal_up():
                return
            run("docker", "rm", "-f", CLIENT)
            run("docker", "run", "-d", "--name", CLIENT, "--network", f"{PROJECT}_default",
                "--cap-add", "NET_ADMIN", "ripsec-strongswan", "/usr/libexec/ipsec/charon")
            wait_for("charon ready",
                     lambda: run("docker", "exec", CLIENT, "swanctl", "--stats").returncode == 0, 20)
            scenario(stack, Cache(secret), organization[1])
        finally:
            if portal.failures:
                print(stack.compose("logs", "--tail", "60", "ripsec").stdout)
            run("docker", "rm", "-f", CLIENT)
            stack.compose("down", "-v", "--remove-orphans")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    portal.PORTAL = "http://localhost:8480"
    main(pathlib.Path(sys.argv[1]).resolve())
    print("all checks passed" if not portal.failures else f"{portal.failures} check(s) failed")
    sys.exit(1 if portal.failures else 0)
