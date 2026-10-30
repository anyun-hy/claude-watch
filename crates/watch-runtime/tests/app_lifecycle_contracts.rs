use claude_watch_core::error::{CoreError, Result};
use claude_watch_runtime::app_lifecycle::*;
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
#[derive(Default)]
struct Fake {
    fail_install: bool,
    resets: usize,
    agent: bool,
    fail_stop: bool,
    commits: usize,
    rollbacks: usize,
    fail_retire: bool,
    retired: bool,
    fail_stop_agent: bool,
}
impl LifecycleOs for Fake {
    fn validate_bundle(&mut self, _: &Path) -> Result<AppIdentity> {
        Ok(AppIdentity {
            bundle_id: BUNDLE_ID.into(),
            executable: "ClaudeWatchMonitor".into(),
            version: "1".into(),
            build: "1".into(),
            architecture: "arm64".into(),
        })
    }
    fn outstanding_transaction(&mut self) -> Result<bool> {
        Ok(false)
    }
    fn stop_app(&mut self, _: &Path) -> Result<()> {
        if self.fail_stop {
            return Err(CoreError::new("app_stop_failed", "fixture"));
        }
        Ok(())
    }
    fn stop_agent(&mut self) -> Result<bool> {
        if self.fail_stop_agent {
            return Err(CoreError::new("agent_stop_failed", "fixture"));
        }
        let x = self.agent;
        self.agent = false;
        Ok(x)
    }
    fn install_agent(&mut self, _: &Path) -> Result<()> {
        if self.fail_install {
            Err(CoreError::new("install_failed", "fixture"))
        } else {
            self.agent = true;
            Ok(())
        }
    }
    fn reset_product_accessibility(&mut self) -> Result<()> {
        self.resets += 1;
        Ok(())
    }
    fn commit_agent_install(&mut self) -> Result<()> {
        self.commits += 1;
        Ok(())
    }
    fn rollback_agent_install(&mut self) -> Result<()> {
        self.rollbacks += 1;
        Ok(())
    }
    fn resume_agent(&mut self, _: &Path) -> Result<()> {
        self.agent = true;
        Ok(())
    }
    fn retire_agent(&mut self, _: &Path) -> Result<()> {
        if self.fail_retire {
            return Err(CoreError::new("agent_retire_failed", "fixture"));
        }
        self.retired = true;
        Ok(())
    }
}
fn bundle(root: &Path, name: &str) -> PathBuf {
    let p = root.join(name);
    fs::create_dir_all(p.join("Contents")).unwrap();
    fs::write(p.join("Contents/Info.plist"), "fixture").unwrap();
    p
}
#[test]
fn replacement_rolls_back_and_never_mutates_protected_data() {
    let root = std::env::temp_dir().join(format!("cw-life-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let app = bundle(&root, "old.app");
    let src = bundle(&root, "new.app");
    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::write(data.join("account"), "keep").unwrap();
    let paths = LifecyclePaths {
        installed: app.clone(),
        trash: root.join("trash"),
        protected_data: data.clone(),
    };
    let mut life = AppLifecycle {
        paths,
        os: Fake {
            fail_install: true,
            resets: 0,
            agent: true,
            ..Default::default()
        },
    };
    assert_eq!(life.apply(&src).unwrap_err().code, "install_failed");
    assert!(app.exists());
    assert!(life.os.agent);
    assert_eq!(life.os.commits, 0);
    assert_eq!(life.os.rollbacks, 1);
    assert_eq!(fs::read_to_string(data.join("account")).unwrap(), "keep");
    let _ = fs::remove_dir_all(root);
}
#[test]
fn protected_data_overlap_is_rejected_before_lifecycle_actions() {
    let root = std::env::temp_dir().join(format!("cw-life-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let app = bundle(&root, "app");
    let mut life = AppLifecycle {
        paths: LifecyclePaths {
            installed: app.clone(),
            trash: root.join("data/trash"),
            protected_data: root.join("data"),
        },
        os: Fake {
            fail_install: false,
            resets: 0,
            agent: false,
            ..Default::default()
        },
    };
    assert_eq!(
        life.plan(Some(&app)).unwrap_err().code,
        "protected_data_overlap"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn failing_to_stop_the_old_app_does_not_move_it_to_failed_new_trash() {
    let root = std::env::temp_dir().join(format!("cw-life-stop-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let app = bundle(&root, "old.app");
    let source = bundle(&root, "source.app");
    fs::write(app.join("old-marker"), b"old unchanged").unwrap();
    let mut lifecycle = AppLifecycle {
        paths: LifecyclePaths {
            installed: app.clone(),
            trash: root.join("trash"),
            protected_data: root.join("data"),
        },
        os: Fake {
            fail_stop: true,
            agent: true,
            ..Default::default()
        },
    };
    assert_eq!(
        lifecycle.apply(&source).unwrap_err().code,
        "app_stop_failed"
    );
    assert_eq!(fs::read(app.join("old-marker")).unwrap(), b"old unchanged");
    assert!(!root.join("trash").exists());
    assert!(lifecycle.os.agent);
    assert_eq!(lifecycle.os.resets, 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failing_to_stop_the_agent_leaves_no_staging_bundle_behind() {
    let root = std::env::temp_dir().join(format!("cw-life-stage-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let app = bundle(&root, "old.app");
    let source = bundle(&root, "source.app");
    let mut lifecycle = AppLifecycle {
        paths: LifecyclePaths {
            installed: app.clone(),
            trash: root.join("trash"),
            protected_data: root.join("data"),
        },
        os: Fake {
            fail_stop_agent: true,
            agent: true,
            ..Default::default()
        },
    };
    assert_eq!(
        lifecycle.apply(&source).unwrap_err().code,
        "agent_stop_failed"
    );
    let staged: Vec<String> = fs::read_dir(&root)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".ClaudeWatch-"))
        .collect();
    assert!(
        staged.is_empty(),
        "staging bundles leaked next to the install target: {staged:?}"
    );
    assert!(app.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn uninstall_preserves_profiles_and_policy_and_restores_app_on_agent_failure() {
    for fail_retire in [false, true] {
        let root = std::env::temp_dir().join(format!("cw-life-remove-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let app = bundle(&root, "installed.app");
        let data = root.join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("account-A"), b"preserve").unwrap();
        let mut life = AppLifecycle {
            paths: LifecyclePaths {
                installed: app.clone(),
                trash: root.join("trash"),
                protected_data: data.clone(),
            },
            os: Fake {
                agent: true,
                fail_retire,
                ..Default::default()
            },
        };
        let result = life.uninstall();
        if fail_retire {
            assert_eq!(result.unwrap_err().code, "agent_retire_failed");
            assert!(app.exists());
            assert!(life.os.agent);
        } else {
            assert!(result.unwrap().join("Contents/Info.plist").is_file());
            assert!(!app.exists());
            assert!(life.os.retired);
            assert!(!life.os.agent);
        }
        // Isolated/nonstandard targets never reset the real product TCC record.
        assert_eq!(life.os.resets, 0);
        assert_eq!(fs::read(data.join("account-A")).unwrap(), b"preserve");
        fs::remove_dir_all(root).unwrap();
    }
}
