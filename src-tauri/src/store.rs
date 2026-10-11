// JSON persistence for tunnel configs.
//
// The store owns a single file `<app_data_dir>/tunnels.json` holding a
// `Vec<TunnelConfig>`. Writes go through a temp-file + rename so a crash can
// never leave a half-written file behind. A corrupted file is treated as an
// empty list (and logged) rather than failing the app.

use std::fs;
use std::path::PathBuf;

use crate::models::TunnelConfig;

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load all tunnel configs. Missing file -> empty list; corrupted file ->
    /// empty list + a log line (the file is only replaced on the next save).
    pub fn load(&self) -> Vec<TunnelConfig> {
        match fs::read_to_string(&self.path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(tunnels) => tunnels,
                Err(e) => {
                    eprintln!(
                        "[pier] {} is corrupted ({e}); treating as empty",
                        self.path.display()
                    );
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                eprintln!("[pier] failed to read {}: {e}", self.path.display());
                Vec::new()
            }
        }
    }

    /// Atomically replace the store file (temp-file + rename via util).
    pub fn save(&self, tunnels: &[TunnelConfig]) -> Result<(), String> {
        let text = serde_json::to_string_pretty(tunnels)
            .map_err(|e| format!("failed to serialize tunnels: {e}"))?;
        crate::util::write_json_atomic(&self.path, &text)
    }

    pub fn get(&self, id: &str) -> Result<Option<TunnelConfig>, String> {
        Ok(self.load().into_iter().find(|t| t.id == id))
    }

    pub fn add(&self, config: TunnelConfig) -> Result<(), String> {
        let mut all = self.load();
        if all.iter().any(|t| t.id == config.id) {
            return Err(format!("tunnel id already exists: {}", config.id));
        }
        all.push(config);
        self.save(&all)
    }

    /// Replace the config with the same id. Returns false when not found.
    pub fn update(&self, config: TunnelConfig) -> Result<bool, String> {
        let mut all = self.load();
        let Some(pos) = all.iter().position(|t| t.id == config.id) else {
            return Ok(false);
        };
        all[pos] = config;
        self.save(&all)?;
        Ok(true)
    }

    /// Delete the config with `id`. Returns false when not found.
    pub fn remove(&self, id: &str) -> Result<bool, String> {
        let mut all = self.load();
        let Some(pos) = all.iter().position(|t| t.id == id) else {
            return Ok(false);
        };
        all.remove(pos);
        self.save(&all)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Backend, TunnelType};

    fn temp_store(tag: &str) -> Store {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "pier-store-test-{tag}-{}.json",
            uuid::Uuid::new_v4()
        ));
        Store::new(p)
    }

    fn sample(id: &str, port: u16) -> TunnelConfig {
        TunnelConfig {
            id: id.to_string(),
            name: format!("test-{id}"),
            tunnel_type: TunnelType::Http,
            backend: Backend::Cloudflare,
            local_host: "127.0.0.1".to_string(),
            local_port: port,
            auto_start: false,
            created_at: "2026-10-06T00:00:00+00:00".to_string(),
            server_id: None,
            subdomain: None,
            remote_port: None,
            auth: None,
            ip_allowlist: Vec::new(),
            cf_tunnel_id: None,
            cf_hostname: None,
            cf_account_id: None,
        }
    }

    fn cleanup(store: &Store) {
        let _ = fs::remove_file(&store.path);
        let _ = fs::remove_file(store.path.with_extension("json.tmp"));
    }

    #[test]
    fn missing_file_loads_empty() {
        let store = temp_store("missing");
        assert!(store.load().is_empty());
        assert!(store.get("nope").unwrap().is_none());
    }

    #[test]
    fn add_update_remove_roundtrip() {
        let store = temp_store("roundtrip");
        store.add(sample("a", 3000)).unwrap();
        store.add(sample("b", 4000)).unwrap();

        let loaded = store.load();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "a");

        let mut updated = sample("a", 3001);
        updated.name = "renamed".into();
        assert!(store.update(updated).unwrap());
        let a = store.get("a").unwrap().unwrap();
        assert_eq!(a.local_port, 3001);
        assert_eq!(a.name, "renamed");

        // Duplicate add is rejected.
        assert!(store.add(sample("a", 3000)).is_err());

        // Update of an unknown id reports false.
        assert!(!store.update(sample("zzz", 1)).unwrap());

        assert!(store.remove("a").unwrap());
        assert!(!store.remove("a").unwrap());
        assert_eq!(store.load().len(), 1);
        cleanup(&store);
    }

    #[test]
    fn corrupted_file_is_treated_as_empty() {
        let store = temp_store("corrupt");
        fs::write(&store.path, "{ not valid json !!!").unwrap();
        assert!(store.load().is_empty());
        // Saving recovers the file.
        store.add(sample("a", 8080)).unwrap();
        assert_eq!(store.get("a").unwrap().unwrap().local_port, 8080);
        cleanup(&store);
    }

    #[test]
    fn save_creates_missing_parent_dirs() {
        let mut p = std::env::temp_dir();
        p.push(format!("pier-store-test-dirs-{}", uuid::Uuid::new_v4()));
        p.push("nested");
        p.push("tunnels.json");
        let store = Store::new(p);
        store.add(sample("a", 8080)).unwrap();
        assert_eq!(store.load().len(), 1);
        cleanup(&store);
    }
}
