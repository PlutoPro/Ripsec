# Keeping device secrets in Cloud Cache

[← README](../README.md)

[Cloud Cache](https://github.com/PlutoPro/Cloud-Cache) is a key-value server with OpenID Connect
authentication, TLS and Raft replication. Ripsec can keep its (already encrypted) device secrets there instead
of in `devices.json`.

**This is optional and experimental.** Without it everything is stored in `data_dir`, which is the simpler
choice for a single server.

- [Try it with Docker](#try-it-with-docker)
- [How it behaves](#how-it-behaves)
- [Setting it up](#setting-it-up)
- [Moving to and from Cloud Cache](#moving-to-and-from-cloud-cache)
- [Troubleshooting](#troubleshooting)

## Try it with Docker

`deploy/full/` runs Ripsec, three Cloud Cache nodes behind HAProxy, Keycloak and the Cloud Cache dashboard.
It uses the compose file in your Cloud Cache checkout, and creates its certificates and the gateway secret
itself.

```sh
git clone https://github.com/PlutoPro/Cloud-Cache.git
git clone https://github.com/PlutoPro/Ripsec.git
cd Ripsec/deploy/full
cp .env.example .env          # set CLOUD_CACHE_DIR to the Cloud-Cache folder
docker compose up -d --build
```

Stop the simple evaluation stack first, as they share ports.

| Address | What | Sign in |
|---|---|---|
| <http://localhost:8480> | VPN portal | `alice` or `bob`, password `change-me` |
| <http://localhost:3100> | Cloud Cache dashboard | `alice` / `alice` |
| <http://localhost:18081> | Keycloak admin | `admin` / `admin` |
| UDP `14500` | VPN, for the Ripsec client on the same Windows machine | |

The dashboard does not list Ripsec's keys: they are in an organisation that no person belongs to.

Things to try while watching `docker compose logs -f ripsec`: `docker compose stop kv1` (enrolling still
works), then `docker compose stop kv1 kv2` (enrolling fails, existing devices still connect, revoking still
takes effect), then `docker compose start kv1 kv2`.

Remove it all, data included, with `docker compose --profile client down -v`. Demo passwords: this stack is for
one machine only.

## How it behaves

| | |
|---|---|
| What is stored | One entry per device: `ripsec:<server_id>:<device_id>`, holding `v1:<ciphertext>` |
| What Cloud Cache can read | Nothing secret: values are AES-256-GCM encrypted with the master key on the VPN server, and bound to the device ID |
| Transport | TLS 1.3 with only the `X25519MLKEM768` key exchange, trusting only the CA you name |
| Sign-in | Keycloak client credentials; the reply must name your organisation ID |
| Enrolling | The device is created only after the write is acknowledged |
| Revoking | Takes effect on the VPN at once. The delete is saved to disk, retried until confirmed, and checked again |
| While running | Secrets are held in memory and re-read every `refresh_seconds`. A tampered or missing entry disables that device |
| Local copy | **None.** |

> **If Cloud Cache is unreachable when Ripsec starts, nobody can connect until it returns.** While Ripsec is
> already running, an outage does not affect existing credentials.

An entry expires 30 days after its credential does, so that an expired device can still be renewed.

## Setting it up

You need a Cloud Cache deployment with **TLS on its TCP API and persistence**, ideally three or more nodes.
Its own guide, [`docs/ripsec.md`](https://github.com/PlutoPro/Cloud-Cache/blob/main/docs/ripsec.md), is the
reference for that side.

### 1. Certificates

Clients and nodes use **different** certificate authorities. For the client-facing certificate, if you have no
CA already:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1825 \
  -subj "/CN=kv CA" -keyout kv-ca.key -out kv-ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=kv" \
  -keyout server.key -out server.csr
printf 'subjectAltName=DNS:kv.example.internal\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA kv-ca.crt -CAkey kv-ca.key -CAcreateserial \
  -days 825 -extfile server.ext -out server.crt
```

Every node presents a certificate with the name Ripsec connects to (the load balancer's, which passes TLS
through): set `TCP_TLS_CERT` and `TCP_TLS_KEY` on each.

### 2. Keycloak

Use two realms: `ripsec` for people, `kv` for Cloud Cache. Create the machine client with Cloud Cache's script:

```sh
export KEYCLOAK_URL=https://sso.example.com
export KEYCLOAK_ADMIN_USER=admin
export KEYCLOAK_ADMIN_PASSWORD=...
export RIPSEC_GATEWAY_SECRET="$(openssl rand -base64 48)"
python3 scripts/ripsec-gateway.py          # in the Cloud-Cache repository
```

It prints the **organisation ID**. Anyone who can administer the `kv` realm can create access to Ripsec's
entries; they could delete or overwrite them, but not read the secrets.

### 3. Ripsec

```toml
[cloud_cache]
address            = "kv.example.internal:7379"   # must match the certificate
ca_file            = "/etc/ripsec/kv-ca.crt"
token_url          = "https://sso.example.com/realms/kv/protocol/openid-connect/token"
# token_ca_file    = "/etc/ripsec/sso-ca.crt"     # if Keycloak uses a private CA
client_id          = "ripsec-gateway"
client_secret_file = "/etc/ripsec/kv-client-secret"
organization_id    = "00000000-0000-0000-0000-000000000000"
refresh_seconds    = 60
```

The client secret comes from `RIPSEC_CLOUD_CACHE_CLIENT_SECRET` or `client_secret_file`, never from the
configuration file itself. `token_url` must be HTTPS.

### 4. Check

Start Ripsec and look for `device secrets are kept in Cloud Cache at ...`, then add a device in the portal.
No `ALERT`, `INCIDENT` or `retrying` lines should follow.

## Moving to and from Cloud Cache

**To it:** add `[cloud_cache]` and restart. Existing secrets are moved over, one at a time, and removed from
`devices.json` once acknowledged. Keep the same master key.

**Away from it:** there is no automatic way back. Ripsec refuses to start if `devices.json` refers to secrets
held remotely and `[cloud_cache]` is missing. Revoke and enrol the devices again.

## Troubleshooting

| Log message | Meaning |
|---|---|
| `Cloud Cache: connect: ...; retrying in ...` | Not reachable: address, firewall, or no healthy node |
| a certificate error while connecting | Wrong CA in `ca_file`, or the certificate does not carry the host name in `address` |
| `ALERT: access token rejected` | Check the `ripsec-gateway` client and its secret |
| `ALERT: ...` naming the organisation | `organization_id` does not match the token |
| `INCIDENT: the entry for ... failed authentication` | An entry was altered, swapped, or written with another master key. Investigate |
| `no secret for ...; the device is disabled` | The entry is gone. Revoke the device and enrol it again |
| `token endpoint: ...` | Keycloak unreachable, wrong `token_url`, or a private CA without `token_ca_file` |
| Portal says "secret store unavailable" | The write was not acknowledged within 20 seconds, usually no majority of nodes |
