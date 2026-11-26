//! Ready to import client configurations.

use crate::config::Vpn;
use crate::ike::crypto;
use crate::net::Cidr;
use crate::store::Device;

fn xml(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            c => c.to_string(),
        })
        .collect()
}

fn uuid() -> String {
    let mut b: [u8; 16] = crypto::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02X}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// A configuration profile for the built-in client of iOS and macOS 26 or later.
pub fn apple(vpn: &Vpn, device: &Device) -> String {
    let sa = "<dict>
          <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key><string>SHA2-384</string>
          <key>DiffieHellmanGroup</key><integer>31</integer>
          <key>PostQuantumKeyExchangeMethods</key><array><integer>36</integer></array>
        </dict>";
    let name = xml(&format!("Ripsec {}", device.name));
    let full_tunnel = u8::from(vpn.local_subnets.iter().any(|n| n.prefix == 0));
    let fallback = u8::from(!vpn.require_pq);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>ripsec.{id}</string>
  <key>PayloadUUID</key><string>{uuid1}</string>
  <key>PayloadDisplayName</key><string>{name}</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>ripsec.{id}.vpn</string>
      <key>PayloadUUID</key><string>{uuid2}</string>
      <key>UserDefinedName</key><string>{name}</string>
      <key>VPNType</key><string>IKEv2</string>
      <key>IPv4</key><dict><key>OverridePrimary</key><integer>{full_tunnel}</integer></dict>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key><string>{address}</string>
        <key>RemoteIdentifier</key><string>{server_id}</string>
        <key>LocalIdentifier</key><string>{id}</string>
        <key>AuthenticationMethod</key><string>SharedSecret</string>
        <key>SharedSecret</key><string>{secret}</string>
        <key>ExtendedAuthEnabled</key><integer>0</integer>
        <key>EnablePFS</key><integer>1</integer>
        <key>AllowPostQuantumKeyExchangeFallback</key><integer>{fallback}</integer>
        <key>IKESecurityAssociationParameters</key>
        {sa}
        <key>ChildSecurityAssociationParameters</key>
        {sa}
      </dict>
    </dict>
  </array>
</dict>
</plist>
"#,
        id = xml(&device.id),
        uuid1 = uuid(),
        uuid2 = uuid(),
        address = xml(&vpn.public_address),
        server_id = xml(&vpn.server_id),
        secret = xml(&device.secret),
    )
}

/// A swanctl.conf for strongSwan 6, as a road warrior or a site-to-site gateway.
pub fn strongswan(vpn: &Vpn, device: &Device) -> String {
    let list = |nets: &[Cidr]| nets.iter().map(Cidr::to_string).collect::<Vec<_>>().join(",");
    let sites = device.subnets();
    let (vips, local_ts) = if sites.is_empty() {
        ("    vips = 0.0.0.0\n".to_string(), String::new())
    } else {
        (String::new(), format!("        local_ts = {}\n", list(&sites)))
    };
    let start = if sites.is_empty() { "none" } else { "trap|start" };
    format!(
        r#"connections {{
  ripsec {{
    version = 2
    remote_addrs = {address}
    proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768
{vips}    dpd_delay = 30s
    local {{
      auth = psk
      id = {id}
    }}
    remote {{
      auth = psk
      id = {server_id}
    }}
    children {{
      net {{
{local_ts}        remote_ts = {remote_ts}
        esp_proposals = aes256gcm16-x25519-ke1_mlkem768
        start_action = {start}
        dpd_action = restart
      }}
    }}
  }}
}}
secrets {{
  ike-ripsec {{
    id-1 = {id}
    id-2 = {server_id}
    secret = "{secret}"
  }}
}}
"#,
        address = vpn.public_address,
        id = device.id,
        server_id = vpn.server_id,
        remote_ts = list(&vpn.local_subnets),
        secret = device.secret,
    )
}
