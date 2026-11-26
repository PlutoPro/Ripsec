# Server setup

[← README](../README.md)

- [Requirements](#requirements)
- [Install](#install)
- [Configuration reference](#configuration-reference)
- [Publishing the portal](#publishing-the-portal)
- [Operating it](#operating-it)
- [Troubleshooting](#troubleshooting)

## Requirements

- A Linux host whose kernel has IPsec (`xfrm_user`, `esp4`).
- UDP **500** and **4500** reachable by clients.
- `CAP_NET_ADMIN`, and permission to bind port 500.
- An OpenID Connect provider ([guide](identity-providers.md)).
- A TLS reverse proxy for the portal.

## Install

Build on the server, or on a machine with the same or an older Linux distribution:

```sh
cargo build --release
sudo install -m 755 target/release/ripsec /usr/local/bin/ripsec
sudo install -d -m 750 /etc/ripsec
sudo install -m 640 deploy/ripsec.example.toml /etc/ripsec/ripsec.toml
sudo nano /etc/ripsec/ripsec.toml
```

Allow forwarding, and masquerade traffic from VPN clients (match your `pool`):

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -m policy --dir out --pol none -j MASQUERADE
```

The `-m policy --dir out --pol none` part matters: without it, traffic that should be encrypted gets
rewritten too. Make both settings permanent with your distribution's usual tools.

Run it:

```sh
sudo ripsec --config /etc/ripsec/ripsec.toml
```

A systemd unit to start from (adjust to your policy; it is not covered by the automated tests):

```ini
# /etc/systemd/system/ripsec.service
[Unit]
Description=Ripsec VPN server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ripsec --config /etc/ripsec/ripsec.toml
EnvironmentFile=-/etc/ripsec/environment
Restart=on-failure
StateDirectory=ripsec
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### With Docker

`deploy/Dockerfile` builds an image that adds the masquerade rule itself. Give it `NET_ADMIN`, the sysctl
`net.ipv4.ip_forward=1`, your configuration at `/etc/ripsec/ripsec.toml`, a volume at `/var/lib/ripsec`, and
publish `500/udp` and `4500/udp`. Set `RIPSEC_POOL` if your pool is not `10.99.0.0/24`.
`deploy/compose.yaml` shows all of it.

## Configuration reference

[`deploy/ripsec.example.toml`](../deploy/ripsec.example.toml) is a commented example. Unknown keys are
rejected, so a typo stops the server instead of being ignored.

### Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | required | IPv4 address for IKE, or `"auto"` for the default route's address |
| `public_address` | required | Host name or address that clients connect to; written into profiles |
| `server_id` | required | The server's IKE identity, usually its host name |
| `pool` | required | Addresses handed to devices, `/16` to `/30` |
| `dns` | none | DNS servers pushed to devices |
| `local_subnets` | `["0.0.0.0/0"]` | What devices may reach. `0.0.0.0/0` is a full tunnel |
| `require_post_quantum` | `true` | Refuse peers that cannot do ML-KEM |
| `data_dir` | `/var/lib/ripsec` | Devices and, by default, the master key |
| `master_key_file` | `<data_dir>/master.key` | Encrypts stored secrets; created on first start |

### `[web]`

| Key | Default | Meaning |
|---|---|---|
| `listen` | required | Address and port of the portal, for example `127.0.0.1:8480` |
| `public_url` | required | The URL users open. Must be `https` unless it is `localhost` |
| `allow_insecure_http` | `false` | Permit plain `http`. For test setups only |

### `[oidc]`

| Key | Default | Meaning |
|---|---|---|
| `issuer` | required | Exactly the provider's `issuer`, trailing slash included |
| `client_id` | required | The portal's client at the provider |
| `client_secret` | none | For confidential clients. Better: `RIPSEC_OIDC_CLIENT_SECRET` |
| `discovery_url` | from `issuer` | If the server reaches the provider under another name |
| `scopes` | `openid profile email` | Requested scopes |
| `roles_claim` | `roles` | ID token claim listing roles or groups; dots descend into objects |
| `admin_role` | `vpn-admin` | Administrators: see and manage everything, add site gateways |
| `user_role` | none | If set, required to use the portal at all. **Without it any account may enrol** |
| `credential_ttl_days` | `7` | How long a device credential lasts before the owner must renew it |
| `max_devices_per_user` | `5` | Per user, sites excluded |

### `[cloud_cache]`

Optional. See [Cloud Cache](cloud-cache.md).

### Environment variables

| Variable | Meaning |
|---|---|
| `RIPSEC_OIDC_CLIENT_SECRET` | Overrides `oidc.client_secret` |
| `RIPSEC_MASTER_KEY` | 32 bytes, base64. Used instead of `master_key_file` |
| `RIPSEC_CLOUD_CACHE_CLIENT_SECRET` | The Cloud Cache gateway client's secret |

## Publishing the portal

The portal speaks plain HTTP and expects a TLS reverse proxy in front. Keep `web.listen` on `127.0.0.1` and set
`public_url` to the HTTPS address. With [Caddy](https://caddyserver.com), for example:

```
vpn.example.com {
    reverse_proxy 127.0.0.1:8480
}
```

The redirect URI to register at your provider is `<public_url>/auth/callback`.

## Operating it

**Back up** `data_dir`, and keep a copy of the master key **somewhere else**. A backup that holds both is as
sensitive as the secrets themselves; a backup of the data without the key cannot be restored.

**Revoking** a device in the portal disconnects it within about a second. Disabling a user at the identity
provider does *not*: revoke their devices too, or wait for the credentials to expire.

**Sites** (gateways with their own subnets) are added by administrators, are not tied to expiry, and cannot be
renewed or limited by `max_devices_per_user`.

**Portal sessions** last one hour and are kept in memory, so a restart signs everyone out. Device
connections have to be made again after a restart.

**After a hard crash** kernel SAs and policies can remain. Clear them with
`ip xfrm state flush; ip xfrm policy flush` (this removes *all* IPsec state on the host).

## Troubleshooting

The server logs to standard error.

| Log message or symptom | Cause |
|---|---|
| `XFRM netlink: ...` at start | Missing `CAP_NET_ADMIN`, or the kernel lacks IPsec |
| `no acceptable IKE proposal` | The client cannot do ML-KEM, or offers only unsupported algorithms |
| `unknown or expired identity` | The device was revoked, has expired, or its secret could not be loaded |
| `authentication failed for ...` | Wrong secret. Add the device again |
| `sign in rejected: ...` | The ID token did not verify; the message says why |
| `provider reports issuer "..."` | `oidc.issuer` differs from the provider's, often by a trailing slash |
| "sign in failed, please try again" in the browser | The portal was opened under a different host name from `public_url`, the login took more than ten minutes, or the server restarted meanwhile |
| Connects, but no traffic | Check forwarding and the masquerade rule |
| Nothing is logged when a client connects | UDP is not arriving. On a Windows host, Windows' own IPsec service holds ports 500 and 4500; publish another port to 4500 |
