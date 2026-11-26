//! Reads the strongSwan profile that the Ripsec portal hands out. Only that shape is
//! understood; this is not a general swanctl.conf parser.

use ripsec_proto::net::Cidr;

#[derive(Debug)]
pub struct Profile {
    pub server: String,
    /// Our IKE identity.
    pub id: String,
    pub server_id: String,
    pub secret: String,
    /// What the server lets us reach.
    pub routes: Vec<Cidr>,
}

impl Profile {
    pub fn parse(text: &str) -> Result<Profile, String> {
        let mut sections: Vec<&str> = Vec::new();
        let (mut server, mut id, mut server_id) = (None, None, None);
        let (mut secret, mut routes, mut site) = (None, None, false);
        for line in text.lines().map(str::trim) {
            if let Some(name) = line.strip_suffix('{') {
                sections.push(name.trim());
            } else if line == "}" {
                sections.pop();
            } else if let Some((key, value)) = line.split_once('=') {
                let value = value.trim().trim_matches('"').to_string();
                match (sections.last().copied().unwrap_or(""), key.trim()) {
                    (_, "remote_addrs") => server = Some(value),
                    ("local", "id") => id = Some(value),
                    ("remote", "id") => server_id = Some(value),
                    (_, "secret") => secret = Some(value),
                    (_, "remote_ts") => routes = Some(value),
                    (_, "local_ts") => site = true,
                    _ => {}
                }
            }
        }
        if site {
            return Err("this is a site-to-site profile; the client only connects as a device".into());
        }
        let routes = routes
            .ok_or("profile has no remote_ts")?
            .split(',')
            .map(str::parse)
            .collect::<Result<Vec<Cidr>, _>>()?;
        Ok(Profile {
            server: server.ok_or("profile has no remote_addrs")?,
            id: id.ok_or("profile has no local id")?,
            server_id: server_id.ok_or("profile has no remote id")?,
            secret: secret.ok_or("profile has no secret")?,
            routes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what `ripsec::web::profiles::strongswan` writes.
    const DEVICE: &str = r#"connections {
  ripsec {
    version = 2
    remote_addrs = vpn.example.com
    proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768
    vips = 0.0.0.0
    dpd_delay = 30s
    local {
      auth = psk
      id = abc@ripsec
    }
    remote {
      auth = psk
      id = vpn.ripsec.test
    }
    children {
      net {
        remote_ts = 10.0.0.0/8,192.168.1.0/24
        esp_proposals = aes256gcm16-x25519-ke1_mlkem768
        start_action = none
        dpd_action = restart
      }
    }
  }
}
secrets {
  ike-ripsec {
    id-1 = abc@ripsec
    id-2 = vpn.ripsec.test
    secret = "s3cr3t_-value"
  }
}
"#;

    #[test]
    fn reads_the_portal_profile() {
        let p = Profile::parse(DEVICE).unwrap();
        assert_eq!((p.server.as_str(), p.id.as_str()), ("vpn.example.com", "abc@ripsec"));
        assert_eq!((p.server_id.as_str(), p.secret.as_str()), ("vpn.ripsec.test", "s3cr3t_-value"));
        assert_eq!(p.routes.len(), 2);
        // Windows line endings are fine.
        assert!(Profile::parse(&DEVICE.replace('\n', "\r\n")).is_ok());
    }

    #[test]
    fn refuses_incomplete_and_site_profiles() {
        assert!(Profile::parse("").is_err());
        assert!(Profile::parse(&DEVICE.replace("secret =", "x =")).is_err());
        let site = DEVICE.replace("remote_ts", "local_ts = 10.60.0.0/24\n        remote_ts");
        assert!(Profile::parse(&site).unwrap_err().contains("site-to-site"));
    }
}
