//! Exact-path app replacement planning. Account, proxy, and guard state are
//! intentionally outside this module's mutation set.
use claude_watch_core::error::{CoreError, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub const APP_NAME: &str = "Claude Watch Monitor.app";
pub const BUNDLE_ID: &str = "io.local.watchpanel";
fn err(c: &str, m: &str) -> CoreError {
    CoreError::new(c, m)
}
fn io(_: std::io::Error) -> CoreError {
    err("app_lifecycle_io", "应用替换文件操作失败")
}
pub trait LifecycleOs {
    fn validate_bundle(&mut self, path: &Path) -> Result<AppIdentity>;
    fn outstanding_transaction(&mut self) -> Result<bool>;
    fn stop_app(&mut self, installed: &Path) -> Result<()>;
    fn stop_agent(&mut self) -> Result<bool>;
    fn install_agent(&mut self, installed: &Path) -> Result<()>;
    fn reset_product_accessibility(&mut self) -> Result<()>;
    fn inspect_installed(&mut self, path: &Path) -> Result<AppIdentity> {
        self.validate_bundle(path)
    }
    fn retire_agent(&mut self, _trash: &Path) -> Result<()> {
        Err(err(
            "lifecycle_adapter_unavailable",
            "未提供主后台任务移除适配器",
        ))
    }
    fn commit_agent_install(&mut self) -> Result<()> {
        Ok(())
    }
    fn rollback_agent_install(&mut self) -> Result<()> {
        Ok(())
    }
    fn resume_agent(&mut self, installed: &Path) -> Result<()> {
        self.install_agent(installed)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    pub bundle_id: String,
    pub executable: String,
    pub version: String,
    pub build: String,
    pub architecture: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePaths {
    pub installed: PathBuf,
    pub trash: PathBuf,
    pub protected_data: PathBuf,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub source: Option<PathBuf>,
    pub installed: PathBuf,
    pub mutates_protected_data: bool,
    pub reset_accessibility: bool,
}
pub struct AppLifecycle<O> {
    pub paths: LifecyclePaths,
    pub os: O,
}
impl<O: LifecycleOs> AppLifecycle<O> {
    pub fn plan(&mut self, source: Option<&Path>) -> Result<MigrationPlan> {
        self.assert_data_boundary()?;
        if let Some(s) = source {
            if same_path(s, &self.paths.installed)? {
                return Err(err("invalid_source", "安装来源不能是当前安装目标"));
            }
            self.verify(s)?;
        }
        if self.paths.installed.exists() {
            let installed = self.paths.installed.clone();
            let identity = self.os.inspect_installed(&installed)?;
            if identity.bundle_id != BUNDLE_ID || identity.executable != "ClaudeWatchMonitor" {
                return Err(err("release_identity_mismatch", "旧应用身份不匹配"));
            }
        }
        if self.os.outstanding_transaction()? {
            return Err(err("recovery_required", "存在未完成的账号、安装或更新事务"));
        }
        Ok(MigrationPlan {
            source: source.map(Path::to_path_buf),
            installed: self.paths.installed.clone(),
            mutates_protected_data: false,
            reset_accessibility: self.paths.installed == Path::new("/Applications").join(APP_NAME),
        })
    }
    pub fn apply(&mut self, source: &Path) -> Result<AppIdentity> {
        let plan = self.plan(Some(source))?;
        let incoming = self.verify(source)?;
        let parent = plan
            .installed
            .parent()
            .ok_or_else(|| err("invalid_app_path", "安装目标缺少父目录"))?;
        fs::create_dir_all(parent).map_err(io)?;
        let stage = parent.join(format!(".ClaudeWatch-{}.app", Uuid::new_v4().simple()));
        let old = self
            .paths
            .trash
            .join(format!("ClaudeWatch-replaced-{}", Uuid::new_v4().simple()))
            .join(APP_NAME);
        // Nothing between here and the swap may leak the staging bundle: a
        // half-copied `.ClaudeWatch-*.app` would otherwise survive in
        // /Applications whenever an early step fails.
        if let Err(error) = copy_dir(source, &stage).and_then(|()| self.verify(&stage).map(|_| ()))
        {
            let _ = fs::remove_dir_all(&stage);
            return Err(error);
        }
        let mut had_agent = false;
        let mut new_installed = false;
        let mut old_moved = false;
        let mut accessibility_reset_attempted = false;
        let result = (|| {
            had_agent = self.os.stop_agent()?;
            self.os.stop_app(&plan.installed)?;
            if plan.installed.exists() {
                fs::create_dir_all(old.parent().unwrap()).map_err(io)?;
                fs::rename(&plan.installed, &old).map_err(io)?;
                old_moved = true;
                if plan.reset_accessibility {
                    accessibility_reset_attempted = true;
                    self.os.reset_product_accessibility()?;
                }
            }
            fs::rename(&stage, &plan.installed).map_err(io)?;
            new_installed = true;
            self.os.install_agent(&plan.installed)?;
            let identity = self.verify(&plan.installed)?;
            self.os.commit_agent_install()?;
            Ok(identity)
        })();
        if let Err(e) = result {
            let explain_permission = |mut error: CoreError| {
                if accessibility_reset_attempted {
                    error.message.push_str("；本次已尝试清理辅助功能授权，应用回退也不能恢复该系统授权，后续仍需重新授权");
                }
                error
            };
            let _ = self.os.stop_agent();
            self.os
                .rollback_agent_install()
                .map_err(explain_permission)?;
            if new_installed && plan.installed.exists() {
                let failed = self
                    .paths
                    .trash
                    .join(format!("failed-new-{}", Uuid::new_v4().simple()));
                let _ = fs::create_dir_all(&self.paths.trash);
                let _ = fs::rename(&plan.installed, failed);
            }
            if old_moved && old.exists() {
                let _ = fs::rename(&old, &plan.installed);
            }
            if had_agent && plan.installed.exists() {
                self.os
                    .resume_agent(&plan.installed)
                    .map_err(explain_permission)?;
            }
            let _ = fs::remove_dir_all(&stage);
            return Err(explain_permission(e));
        }
        Ok(incoming)
    }
    pub fn uninstall(&mut self) -> Result<PathBuf> {
        if !self.paths.installed.exists() {
            return Err(err("app_missing", "未找到本产品，未清理其他程序或权限"));
        }
        let plan = self.plan(None)?;
        let had_agent = self.os.stop_agent()?;
        let destination = self
            .paths
            .trash
            .join(format!("ClaudeWatch-removed-{}", Uuid::new_v4().simple()));
        let old = destination.join(APP_NAME);
        let mut moved = false;
        let result = (|| {
            self.os.stop_app(&plan.installed)?;
            fs::create_dir_all(&destination).map_err(io)?;
            fs::rename(&plan.installed, &old).map_err(io)?;
            moved = true;
            if plan.reset_accessibility {
                self.os.reset_product_accessibility()?;
            }
            self.os.retire_agent(&destination)?;
            Ok(())
        })();
        if let Err(error) = result {
            if moved && !plan.installed.exists() {
                fs::rename(&old, &plan.installed).map_err(io)?;
            }
            if had_agent && plan.installed.exists() {
                self.os.resume_agent(&plan.installed)?;
            }
            return Err(error);
        }
        Ok(old)
    }
    fn verify(&mut self, path: &Path) -> Result<AppIdentity> {
        let m = fs::symlink_metadata(path).map_err(io)?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(err("invalid_app_bundle", "应用路径不是普通目录"));
        }
        let x = self.os.validate_bundle(path)?;
        if x.bundle_id != BUNDLE_ID
            || x.executable != "ClaudeWatchMonitor"
            || x.architecture != "arm64"
        {
            return Err(err(
                "release_identity_mismatch",
                "应用标识、可执行文件或架构不匹配",
            ));
        }
        Ok(x)
    }
    fn assert_data_boundary(&self) -> Result<()> {
        let protected = canonical_or_absolute(&self.paths.protected_data)?;
        for candidate in [&self.paths.installed, &self.paths.trash] {
            let candidate = canonical_or_absolute(candidate)?;
            if candidate == protected
                || candidate.starts_with(&protected)
                || protected.starts_with(&candidate)
            {
                return Err(err(
                    "protected_data_overlap",
                    "应用、暂存或废纸篓路径不能包含账户和策略数据",
                ));
            }
        }
        Ok(())
    }
}
fn canonical_or_absolute(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        fs::canonicalize(path).map_err(io)
    } else {
        Ok(path.to_path_buf())
    }
}
fn same_path(a: &Path, b: &Path) -> Result<bool> {
    if !b.exists() {
        return Ok(false);
    }
    Ok(fs::canonicalize(a).map_err(io)? == fs::canonicalize(b).map_err(io)?)
}
fn copy_dir(s: &Path, t: &Path) -> Result<()> {
    if t.exists() {
        return Err(err("app_stage_conflict", "应用暂存路径已存在"));
    }
    fs::create_dir_all(t).map_err(io)?;
    for e in fs::read_dir(s).map_err(io)? {
        let e = e.map_err(io)?;
        let p = e.path();
        let d = t.join(e.file_name());
        let m = fs::symlink_metadata(&p).map_err(io)?;
        if m.file_type().is_symlink() {
            return Err(err("invalid_app_bundle", "应用包含符号链接"));
        }
        if m.is_dir() {
            copy_dir(&p, &d)?
        } else if m.is_file() {
            fs::copy(p, d).map_err(io)?;
        } else {
            return Err(err("invalid_app_bundle", "应用包含特殊文件"));
        }
    }
    Ok(())
}
