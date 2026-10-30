use claude_watch_core::region::{valid_timezone_name, ZoneCatalog};
use std::{fs::File, io::Read, path::Path};

pub fn load_system_catalog() -> ZoneCatalog {
    let mut result = ZoneCatalog::new();
    for path in [
        "/usr/share/zoneinfo/zone.tab",
        "/usr/share/zoneinfo/zone1970.tab",
        "/var/db/timezone/zoneinfo/zone.tab",
    ] {
        let Ok(file) = File::open(path) else {
            continue;
        };
        let mut data = String::new();
        if file.take(2_000_001).read_to_string(&mut data).is_err() || data.len() > 2_000_000 {
            continue;
        }
        for line in data
            .lines()
            .filter(|v| !v.starts_with('#') && !v.is_empty())
        {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() < 3 || !valid_timezone_name(fields[2]) {
                continue;
            }
            let valid = ["/usr/share/zoneinfo", "/var/db/timezone/zoneinfo"]
                .iter()
                .any(|base| {
                    let Ok(mut f) = File::open(Path::new(base).join(fields[2])) else {
                        return false;
                    };
                    let mut magic = [0; 4];
                    f.read_exact(&mut magic).is_ok() && &magic == b"TZif"
                });
            if !valid {
                continue;
            }
            for country in fields[0]
                .split(',')
                .filter(|c| c.len() == 2 && c.bytes().all(|v| v.is_ascii_uppercase()))
            {
                result
                    .entry(country.into())
                    .or_default()
                    .insert(fields[2].into());
            }
        }
    }
    result
}

/// Process-wide copy of `load_system_catalog`.
///
/// The catalog is read from `zone.tab` and validated against the TZif magic of
/// every listed zone, so it is loaded once and shared.  Callers that decide
/// whether a country already implies a single timezone must not repeat that
/// work on every audit round.
pub fn system_catalog() -> &'static ZoneCatalog {
    static CATALOG: std::sync::OnceLock<ZoneCatalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(load_system_catalog)
}
