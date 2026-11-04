//! Signed releases and bounded ZIP extraction. Network and installation are
//! injected; an absent source/key is explicitly unconfigured, never online.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use claude_watch_core::error::{CoreError, Result};
use rsa::sha2::{Digest, Sha256};
use rsa::{pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, signature::Verifier, RsaPublicKey};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use zip::ZipArchive;

mod permissions;
pub const MAX_ARCHIVE: u64 = 1024 * 1024 * 1024;
pub const MAX_EXPANDED: u64 = 2 * MAX_ARCHIVE;
const MAX_FILES: usize = 100_000;
fn err(c: &str, m: &str) -> CoreError {
    CoreError::new(c, m)
}
fn io(_: std::io::Error) -> CoreError {
    err("update_io_failed", "更新文件操作失败")
}
pub trait UpdateOs {
    fn architecture(&mut self) -> Result<String>;
    fn verify_app(&mut self, path: &Path, version: &str) -> Result<()>;
    fn health(&mut self) -> Result<()>;
    fn installed_version(&mut self, _app: &Path) -> Result<String> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供已装版本",
        ))
    }
    fn macos_version(&mut self) -> Result<(u64, u64)> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供系统版本",
        ))
    }
    fn app_running(&mut self, _app: &Path) -> Result<bool> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供应用运行状态",
        ))
    }
    fn root_helper_hash(&mut self) -> Result<Option<String>> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供系统组件状态",
        ))
    }
    fn should_reset_accessibility(&self, app: &Path) -> bool {
        app == Path::new("/Applications/Claude Watch Monitor.app")
    }
    fn reset_accessibility(&mut self, _app: &Path, _bundle: &str) -> Result<()> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供辅助功能重置",
        ))
    }
    fn restart_agent(&mut self) -> Result<()> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供后台重启",
        ))
    }
    fn agent_healthy(&mut self) -> Result<bool> {
        Err(err(
            "update_adapter_unavailable",
            "更新适配器未提供后台健康状态",
        ))
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub archive_url: String,
    pub archive_sha256: String,
    pub architecture: String,
    pub files: std::collections::BTreeMap<String, String>,
}
pub fn check_configured(url: &str, key: &str) -> Result<()> {
    if url.is_empty() || key.is_empty() {
        return Err(err(
            "update_unconfigured",
            "尚未配置自有发布源和固定公钥；未连接上游 main",
        ));
    }
    if !safe_https(url) {
        return Err(err(
            "unsafe_update_url",
            "更新地址必须是无凭据的 HTTPS 地址",
        ));
    }
    Ok(())
}
pub fn verify_manifest(
    payload: &[u8],
    signature: &[u8],
    public_pem: &str,
    architecture: &str,
) -> Result<Release> {
    if payload.len() > 2_000_000
        || signature.len() > 8192
        || !public_pem.contains("BEGIN PUBLIC KEY")
        || public_pem.len() > 16384
    {
        return Err(err("invalid_release", "更新清单或固定公钥格式错误"));
    }
    let key = RsaPublicKey::from_public_key_pem(public_pem)
        .map_err(|_| err("update_key_missing", "需要固定的 RSA 发布公钥"))?;
    let verifier = VerifyingKey::<Sha256>::new(key);
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| err("release_signature_invalid", "更新签名格式错误"))?;
    verifier
        .verify(payload, &sig)
        .map_err(|_| err("release_signature_invalid", "更新签名不符合固定发布公钥"))?;
    let v = crate::storage::strict_json(payload)
        .map_err(|_| err("invalid_release", "签名清单不是有效 JSON"))?;
    if v["schema"] != 1 || v["runtime_schema"] != 2 || v["admin_abi"] != 1 {
        return Err(err(
            "release_incompatible",
            "更新协议、数据格式或管理组件接口不兼容",
        ));
    }
    let version = v["version"]
        .as_str()
        .ok_or_else(|| err("invalid_release_version", "缺少版本号"))?;
    version_tuple(version)?;
    let arch = v["architecture"]
        .as_str()
        .ok_or_else(|| err("invalid_release", "缺少架构"))?;
    if arch != architecture && arch != "universal" {
        return Err(err("architecture_mismatch", "更新包架构不匹配"));
    }
    let files = v["files"]
        .as_object()
        .filter(|x| !x.is_empty())
        .ok_or_else(|| err("invalid_release", "缺少完整文件清单"))?
        .iter()
        .map(|(k, v)| {
            Ok((
                safe_member(k)?,
                v.as_str()
                    .filter(|x| x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit()))
                    .ok_or_else(|| err("invalid_release", "文件哈希无效"))?
                    .into(),
            ))
        })
        .collect::<Result<_>>()?;
    let archive_sha256 = v["archive_sha256"]
        .as_str()
        .filter(|x| x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| err("invalid_release", "归档哈希无效"))?
        .into();
    let archive_url = v["archive_url"]
        .as_str()
        .ok_or_else(|| err("invalid_release", "缺少归档地址"))?
        .into();
    Ok(Release {
        version: version.into(),
        archive_url,
        archive_sha256,
        architecture: arch.into(),
        files,
    })
}
pub fn verify_extract(archive: &Path, destination: &Path, release: &Release) -> Result<()> {
    let meta = fs::metadata(archive).map_err(io)?;
    if meta.len() > MAX_ARCHIVE {
        return Err(err("oversize_release", "更新包超过大小上限"));
    }
    let mut z = ZipArchive::new(fs::File::open(archive).map_err(io)?)
        .map_err(|_| err("invalid_release", "更新归档无效"))?;
    let mut seen = BTreeSet::new();
    let mut expanded = 0u64;
    for i in 0..z.len() {
        let mut f = z
            .by_index(i)
            .map_err(|_| err("invalid_release", "更新归档条目无效"))?;
        let name = safe_member(f.name())?;
        if !seen.insert(name.clone()) {
            return Err(err("unsafe_archive", "更新包包含重复路径"));
        }
        if seen.len() > MAX_FILES {
            return Err(err("oversize_release", "更新包文件数过多"));
        }
        permissions::validate_entry(f.is_dir(), f.unix_mode())?;
        if f.is_dir() {
            continue;
        }
        if !release.files.contains_key(&name) {
            return Err(err("unlisted_file", "更新包存在未签名列出的文件"));
        }
        expanded = expanded
            .checked_add(f.size())
            .ok_or_else(|| err("oversize_release", "更新包过大"))?;
        if expanded > MAX_EXPANDED {
            return Err(err("oversize_release", "更新包展开后过大"));
        }
        let target = permissions::prepare_parent(destination, &name)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .map_err(io)?;
        out.set_permissions(fs::Permissions::from_mode(0o600)).map_err(io)?;
        let mut h = Sha256::new();
        let mut b = [0u8; 65536];
        loop {
            let n = f.read(&mut b).map_err(io)?;
            if n == 0 {
                break;
            }
            h.update(&b[..n]);
            out.write_all(&b[..n]).map_err(io)?;
        }
        let actual = hex(h.finalize().as_slice());
        if actual != release.files[&name] {
            return Err(err("release_hash_mismatch", "更新文件校验失败"));
        }
    }
    if seen
        .iter()
        .filter(|x| !x.ends_with('/'))
        .collect::<BTreeSet<_>>()
        != release.files.keys().collect()
    {
        return Err(err("release_incomplete", "更新包文件缺失"));
    }
    for required in [
        "runtime/watch-engine",
        "runtime/watch-native-observer",
        "runtime/BuildInfo.plist",
        "runtime/watch-admin.sh",
        "runtime/watch-process-control",
        "app/Claude Watch Monitor.app/Contents/Info.plist",
    ] {
        if !release.files.contains_key(required) {
            return Err(err("release_incomplete", "更新包缺少必要组件"));
        }
    }
    for name in [
        "watch-engine",
        "watch-native-observer",
        "watch-process-control",
        "watch-admin.sh",
        "BuildInfo.plist",
    ] {
        let runtime = format!("runtime/{name}");
        let bundled = format!("app/Claude Watch Monitor.app/Contents/Resources/{name}");
        if !release.files.contains_key(&runtime)
            || release.files.get(&runtime) != release.files.get(&bundled)
        {
            return Err(err(
                "release_component_mismatch",
                "应用与后台的原生组件不一致或缺失",
            ));
        }
    }
    // No execution bits until the complete listed payload and matching
    // bundled/runtime components have passed content validation.
    permissions::apply(destination, release)
}
pub fn archive_hash(archive: &Path) -> Result<String> {
    let mut f = fs::File::open(archive).map_err(io)?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    loop {
        let n = f.read(&mut b).map_err(io)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex(h.finalize().as_slice()))
}
pub fn version_tuple(v: &str) -> Result<(u64, u64, u64)> {
    let p: Vec<_> = v.split('.').collect();
    if p.len() != 3 {
        return Err(err("invalid_release_version", "版本号必须为三段数字"));
    }
    let n: Vec<_> = p
        .iter()
        .map(|x| x.parse::<u64>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| err("invalid_release_version", "版本号必须为三段数字"))?;
    Ok((n[0], n[1], n[2]))
}
fn safe_https(v: &str) -> bool {
    url::Url::parse(v).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
    }) && !v.contains(char::is_whitespace)
}
fn same_origin(a: &str, b: &str) -> bool {
    safe_https(a)
        && safe_https(b)
        && url::Url::parse(a)
            .ok()
            .zip(url::Url::parse(b).ok())
            .is_some_and(|(a, b)| a.origin() == b.origin())
}
fn safe_member(n: &str) -> Result<String> {
    let p = Path::new(n);
    if n.is_empty()
        || n.contains('\\')
        || n.contains('\0')
        || p.is_absolute()
        || n.strip_suffix('/').unwrap_or(n).split('/').any(|part| matches!(part, "" | "." | ".."))
        || p.components().any(|x| matches!(x, Component::ParentDir))
        || !matches!(p.components().next(),Some(Component::Normal(x)) if x=="app"||x=="runtime")
        || n.ends_with(".py")
        || p.file_name()
            .is_some_and(|x| x == "claude-watch.sh" || x == "snapshot.sh")
    {
        return Err(err("unsafe_archive", "更新包包含不安全路径"));
    }
    Ok(n.into())
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char)
    }
    s
}

pub trait Transport {
    fn get(&mut self, url: &str, limit: u64) -> Result<Vec<u8>>;
}
/// Bounded concrete HTTPS transport. It is never called by `check` unless a
/// fixed source and fixed public key have both been supplied.
pub struct UreqTransport;
impl Transport for UreqTransport {
    fn get(&mut self, url: &str, limit: u64) -> Result<Vec<u8>> {
        if !safe_https(url) {
            return Err(err("unsafe_update_url", "更新地址必须是 HTTPS"));
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .timeout_global(Some(std::time::Duration::from_secs(
                if limit <= 3_000_000 { 15 } else { 120 },
            )))
            .build()
            .into();
        let response = agent
            .get(url)
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|_| err("update_download_failed", "更新下载失败"))?;
        if response.status().as_u16() != 200 {
            return Err(err("update_download_failed", "更新源未返回完整内容"));
        }
        let r = response.into_body().into_reader();
        let mut v = Vec::new();
        r.take(limit + 1).read_to_end(&mut v).map_err(io)?;
        if v.len() as u64 > limit {
            return Err(err("oversize_release", "下载内容过大"));
        }
        Ok(v)
    }
}
#[derive(Debug, Clone)]
pub struct UpdatePaths {
    pub base: PathBuf,
    pub app: PathBuf,
    pub watch: PathBuf,
    /// Recovery-only target for existing schema-1 journals. Native releases
    /// never create, overwrite or remove the old business script.
    pub backend: PathBuf,
}
pub struct Updater<O, T> {
    pub paths: UpdatePaths,
    pub os: O,
    pub transport: T,
}
impl<O: UpdateOs, T: Transport> Updater<O, T> {
    pub fn check(&mut self, url: &str, key: &str, apply: bool) -> Result<Value> {
        check_configured(url, key)?;
        let envelope = self.transport.get(url, 3_000_000)?;
        let e = crate::storage::strict_json(&envelope)
            .map_err(|_| err("invalid_release", "更新信封格式错误"))?;
        let payload = STANDARD
            .decode(
                e["manifest"]
                    .as_str()
                    .ok_or_else(|| err("invalid_release", "缺少清单"))?,
            )
            .map_err(|_| err("invalid_release", "更新清单格式错误"))?;
        let signature = STANDARD
            .decode(
                e["signature"]
                    .as_str()
                    .ok_or_else(|| err("invalid_release", "缺少签名"))?,
            )
            .map_err(|_| err("invalid_release", "更新清单格式错误"))?;
        if payload.len() > 2_000_000 || signature.len() > 8192 {
            return Err(err("invalid_release", "更新清单格式错误"));
        }
        let release = verify_manifest(&payload, &signature, key, &self.os.architecture()?)?;
        let current = self.os.installed_version(&self.paths.app)?;
        if version_tuple(&release.version)? <= version_tuple(&current)? {
            return Ok(serde_json::json!({"status":"current","version":current}));
        }
        if !apply {
            return Ok(
                serde_json::json!({"status":"available","version":release.version,"apply_required":true}),
            );
        }
        let archive_url = &release.archive_url;
        if !safe_https(archive_url) {
            return Err(err(
                "unsafe_update_url",
                "更新地址必须是无凭据的 HTTPS 地址",
            ));
        }
        if !same_origin(url, archive_url) {
            return Err(err(
                "update_origin_mismatch",
                "清单与更新包必须来自同一已配置发布源",
            ));
        }
        if self.os.app_running(&self.paths.app)? {
            return Ok(
                serde_json::json!({"status":"deferred","version":release.version,"message":"退出监控界面后可应用完整更新"}),
            );
        }
        let bytes = self.transport.get(archive_url, MAX_ARCHIVE)?;
        let dir = self
            .paths
            .base
            .join(format!("update-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).map_err(io)?;
        let zip = dir.join("release.zip");
        fs::write(&zip, &bytes).map_err(io)?;
        if archive_hash(&zip)? != release.archive_sha256 {
            return Err(err("archive_hash_mismatch", "更新包整体校验失败"));
        }
        let payload_dir = dir.join("payload");
        fs::create_dir(&payload_dir).map_err(io)?;
        verify_extract(&zip, &payload_dir, &release)?;
        if let Some(hash) = self.os.root_helper_hash()? {
            if release.files.get("runtime/watch-admin.sh") != Some(&hash) {
                return Ok(
                    serde_json::json!({"status":"administrator_required","version":release.version,"message":"系统组件需要管理员升级；整包尚未应用"}),
                );
            }
        }
        self.apply_payload(&payload_dir, &release)?;
        let _ = fs::remove_dir_all(dir);
        Ok(
            serde_json::json!({"status":"ok","version":release.version,"message":"完整组件已更新并通过组件自检；不代表账号实机验收"}),
        )
    }
    pub fn apply_payload(&mut self, source: &Path, release: &Release) -> Result<()> {
        let targets = [
            (
                source.join("app/Claude Watch Monitor.app"),
                self.paths.app.clone(),
            ),
            (source.join("runtime"), self.paths.watch.join("runtime")),
        ];
        for (s, _) in &targets {
            if !s.exists() {
                return Err(err("release_incomplete", "更新包缺少组件"));
            }
        }
        fs::create_dir_all(&self.paths.base).map_err(io)?;
        let journal = self.paths.base.join("update-transaction.json");
        if journal.exists() {
            return Err(err("recovery_required", "先恢复未完成更新事务"));
        }
        let mut records = Vec::new();
        for (incoming, target) in &targets {
            if target.with_extension("cw-new").exists() || target.with_extension("cw-old").exists()
            {
                return Err(err("recovery_required", "更新暂存路径已经存在，未覆盖"));
            }
            records.push(serde_json::json!({"target":target,"stage":target.with_extension("cw-new"),"old":target.with_extension("cw-old"),"existed":target.exists(),"started":false,
                "before":if target.exists(){Some(crate::agent_install::tree(target)?)}else{None},"after":crate::agent_install::tree(incoming)?}));
        }
        let previous_release = self.paths.base.join("release.json");
        let previous_release = if previous_release.exists() {
            Some(
                crate::storage::strict_json(&fs::read(&previous_release).map_err(io)?)
                    .map_err(|_| err("invalid_state", "旧发布记录损坏"))?,
            )
        } else {
            None
        };
        let mut j = serde_json::json!({"schema":2,"phase":"prepared","version":release.version,"previous_release":previous_release,"records":records});
        atomic(&journal, &j)?;
        let result = (|| {
            for (i, (incoming, target)) in targets.iter().enumerate() {
                let r = &mut j["records"][i];
                let stage = PathBuf::from(r["stage"].as_str().unwrap());
                let old = PathBuf::from(r["old"].as_str().unwrap());
                r["started"] = Value::Bool(true);
                atomic(&journal, &j)?;
                copy_entry(incoming, &stage)?;
                if serde_json::to_value(crate::agent_install::tree(&stage)?)
                    .map_err(|_| err("invalid_update_journal", "组件清单无法编码"))?
                    != j["records"][i]["after"]
                {
                    return Err(err("update_source_changed", "复制期间更新组件发生变化"));
                }
                if target.exists() {
                    fs::rename(target, &old).map_err(io)?
                }
                fs::rename(stage, target).map_err(io)?;
            }
            self.os.verify_app(&self.paths.app, &release.version)?;
            self.os.health()?;
            if self.os.should_reset_accessibility(&self.paths.app) {
                // TCC is managed by macOS and cannot be rolled back. Record the
                // attempt before invoking it so interrupted recovery is honest.
                j["accessibility_reset_attempted"] = Value::Bool(true);
                atomic(&journal, &j)?;
                self.os
                    .reset_accessibility(&self.paths.app, "io.local.watchpanel")?;
            }
            self.os.restart_agent()?;
            if !self.os.agent_healthy()? {
                return Err(err("update_health_failed", "新版后台未产生有效心跳"));
            }
            atomic(
                &self.paths.base.join("release.json"),
                &serde_json::json!({"version":release.version,"runtime_schema":2}),
            )?;
            j["phase"] = Value::String("committed".into());
            atomic(&journal, &j)?;
            self.recover().map(|_| ())
        })();
        if let Err(e) = result {
            let reauthorization = self.recover()?;
            if reauthorization {
                return Err(err("update_rolled_back_reauthorization_required",&format!("更新未完成，应用和后台已恢复；辅助功能授权可能已被清除，需在系统提示中重新授权。原因为：{}",e.message)));
            }
            return Err(e);
        }
        Ok(())
    }
    pub fn recover(&mut self) -> Result<bool> {
        let result = self.recover_inner();
        if let Err(mut e) = result {
            let p = self.paths.base.join("update-transaction.json");
            let flagged = fs::symlink_metadata(&p).is_ok_and(|m| {
                m.is_file() && !m.file_type().is_symlink() && m.len() <= 32 * 1024 * 1024
            }) && fs::read(&p)
                .ok()
                .and_then(|bytes| crate::storage::strict_json(&bytes).ok())
                .is_some_and(|j: Value| {
                    j["phase"] != "committed" && j["accessibility_reset_attempted"] == true
                });
            if flagged {
                e.message
                    .push_str("；辅助功能授权可能已被清除，恢复后需在系统提示中重新授权");
            }
            return Err(e);
        }
        result
    }
    fn recover_inner(&mut self) -> Result<bool> {
        let p = self.paths.base.join("update-transaction.json");
        if !p.exists() {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(&p).map_err(io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > 32 * 1024 * 1024
        {
            return Err(err("invalid_update_journal", "恢复记录路径或大小无效"));
        }
        let j: Value = crate::storage::strict_json(&fs::read(&p).map_err(io)?)
            .map_err(|_| err("invalid_update_journal", "更新恢复记录无效"))?;
        let rs = j["records"]
            .as_array()
            .filter(|x| (j["schema"] == 1 && x.len() == 3) || (j["schema"] == 2 && x.len() == 2))
            .ok_or_else(|| err("invalid_update_journal", "更新恢复记录无效"))?;
        if j["schema"] != 1 && j["schema"] != 2 {
            return Err(err("invalid_update_journal", "更新恢复记录版本无效"));
        }
        let mut expected = vec![self.paths.app.clone(), self.paths.watch.join("runtime")];
        if j["schema"] == 1 {
            expected.push(self.paths.backend.clone());
        }
        let mut owned = std::collections::BTreeSet::new();
        for (r, expected_target) in rs.iter().zip(expected.iter()) {
            let target = PathBuf::from(
                r["target"]
                    .as_str()
                    .ok_or_else(|| err("invalid_update_journal", "路径无效"))?,
            );
            let old = PathBuf::from(
                r["old"]
                    .as_str()
                    .ok_or_else(|| err("invalid_update_journal", "路径无效"))?,
            );
            let stage = PathBuf::from(
                r["stage"]
                    .as_str()
                    .ok_or_else(|| err("invalid_update_journal", "路径无效"))?,
            );
            let expected_stage = expected_target.with_extension("cw-new");
            let expected_old = expected_target.with_extension("cw-old");
            if target != *expected_target
                || stage != expected_stage
                || old != expected_old
                || !owned.insert(target.clone())
                || !owned.insert(stage.clone())
                || !owned.insert(old.clone())
            {
                return Err(err("invalid_update_journal", "更新恢复路径无效"));
            }
            for candidate in [&target, &old, &stage] {
                if fs::symlink_metadata(candidate)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    return Err(err("invalid_update_journal", "更新恢复路径包含符号链接"));
                }
            }
            if j["schema"] == 2
                && (!r["existed"].is_boolean()
                    || !r["started"].is_boolean()
                    || !r["after"].is_object()
                    || (r["existed"] == true && !r["before"].is_object()))
            {
                return Err(err("invalid_update_journal", "原生更新恢复清单或阶段无效"));
            }
            if j["schema"] == 2 && j["phase"] != "committed" {
                if old.exists()
                    && serde_json::to_value(crate::agent_install::tree(&old)?)
                        .map_err(|_| err("invalid_update_journal", "恢复清单无法编码"))?
                        != r["before"]
                {
                    return Err(err(
                        "update_rollback_conflict",
                        "旧组件被外部修改，保留恢复记录",
                    ));
                }
                if target.exists() && r["started"] == true {
                    let actual = serde_json::to_value(crate::agent_install::tree(&target)?)
                        .map_err(|_| err("invalid_update_journal", "恢复清单无法编码"))?;
                    if actual != r["after"] && actual != r["before"] {
                        return Err(err("update_rollback_conflict", "组件被外部修改，未覆盖"));
                    }
                }
            }
        }
        for r in rs.iter().rev() {
            let target = PathBuf::from(r["target"].as_str().unwrap());
            let old = PathBuf::from(r["old"].as_str().unwrap());
            let stage = PathBuf::from(r["stage"].as_str().unwrap());

            if j["phase"] != "committed" && old.exists() {
                remove(&target)?;
                fs::rename(old, target).map_err(io)?
            } else if j["phase"] == "committed" {
                let _ = remove(&old);
            } else if j["schema"] == 2 && r["existed"] == false && r["started"] == true {
                remove(&target)?;
            }
            let _ = remove(&stage);
        }
        if j["phase"] != "committed" {
            let release = self.paths.base.join("release.json");
            if j["previous_release"].is_null() {
                if release.exists() {
                    fs::remove_file(&release).map_err(io)?;
                }
            } else {
                atomic(&release, &j["previous_release"])?;
            }
            // Restoring bytes alone does not restore a daemon which has
            // already restarted into the failed release. Preserve unloaded
            // preference in the concrete adapter; never start another job.
            if rs.iter().any(|r| r["started"] == true) {
                self.os.restart_agent()?;
            }
        }
        fs::remove_file(p).map_err(io)?;
        Ok(j["phase"] != "committed" && j["accessibility_reset_attempted"] == true)
    }
}
fn atomic(p: &Path, v: &Value) -> Result<()> {
    let data = serde_json::to_vec(v).map_err(|_| err("invalid_update_journal", "无法编码事务"))?;
    if fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(err("unsafe_update_path", "更新记录是符号链接，未写入"));
    }
    let parent = p
        .parent()
        .ok_or_else(|| err("unsafe_update_path", "更新记录路径无效"))?;
    let temp = parent.join(format!(".update-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(io)?;
        file.write_all(&data)
            .and_then(|_| file.sync_all())
            .map_err(io)?;
        fs::rename(&temp, p).map_err(io)?;
        fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
fn copy_entry(s: &Path, t: &Path) -> Result<()> {
    if s.is_dir() {
        copy_dir(s, t)
    } else {
        if let Some(p) = t.parent() {
            fs::create_dir_all(p).map_err(io)?
        }
        fs::copy(s, t).map_err(io)?;
        Ok(())
    }
}
fn copy_dir(s: &Path, t: &Path) -> Result<()> {
    fs::create_dir_all(t).map_err(io)?;
    for e in fs::read_dir(s).map_err(io)? {
        let e = e.map_err(io)?;
        let p = e.path();
        let d = t.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &d)?
        } else {
            fs::copy(p, d).map_err(io)?;
        }
    }
    Ok(())
}
fn remove(p: &Path) -> Result<()> {
    if p.is_dir() {
        fs::remove_dir_all(p).map_err(io)
    } else if p.exists() {
        fs::remove_file(p).map_err(io)
    } else {
        Ok(())
    }
}
