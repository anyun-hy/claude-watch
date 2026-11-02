//! Process execution boundary. The flow never calls `std::process::Command`
//! itself, so tests can answer every system call deterministically.
use crate::blocked;
use claude_watch_core::error::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// The child owns the terminal: the sudo password prompt and the package
    /// script's build output must reach the user.
    Inherit,
    /// The child's output is collected instead of shown.
    Capture,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status == 0
    }
    /// `defaults` and `launchctl` report a missing entry with exit code 1 and
    /// 113 respectively; anything else is a real failure.
    fn mentions_missing(&self) -> bool {
        let text = self.stderr.to_lowercase();
        text.contains("not found") || text.contains("does not exist")
    }
    pub fn key_missing(&self) -> bool {
        self.status == 1 && self.mentions_missing()
    }
}

pub trait Runner {
    fn locate(&self, name: &str) -> Option<PathBuf>;
    fn run(
        &self,
        args: &[String],
        env: Option<&BTreeMap<String, String>>,
        mode: RunMode,
    ) -> Result<Output>;
}

pub struct SystemRunner;

impl SystemRunner {
    fn argv(args: &[String]) -> Result<()> {
        if args.is_empty() || args.iter().any(|value| value.contains('\0')) {
            return Err(blocked("命令参数无效。"));
        }
        Ok(())
    }
}

impl Runner for SystemRunner {
    fn locate(&self, name: &str) -> Option<PathBuf> {
        let candidate = Path::new(name);
        if candidate.is_absolute() {
            return candidate.is_file().then(|| candidate.to_path_buf());
        }
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|entry| entry.is_file())
    }
    fn run(
        &self,
        args: &[String],
        env: Option<&BTreeMap<String, String>>,
        mode: RunMode,
    ) -> Result<Output> {
        Self::argv(args)?;
        let mut command = std::process::Command::new(&args[0]);
        command.args(&args[1..]);
        if let Some(values) = env {
            command.envs(values);
        }
        match mode {
            RunMode::Inherit => {
                let status = command
                    .status()
                    .map_err(|error| blocked(format_command(&args[0], error)))?;
                Ok(Output {
                    status: status.code().unwrap_or(-1),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
            RunMode::Capture => {
                let output = command
                    .output()
                    .map_err(|error| blocked(format_command(&args[0], error)))?;
                Ok(Output {
                    status: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                })
            }
        }
    }
}

fn format_command(program: &str, error: std::io::Error) -> String {
    let name = Path::new(program)
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string());
    let reason = error
        .raw_os_error()
        .map(|code| std::io::Error::from_raw_os_error(code).to_string())
        .unwrap_or_else(|| "系统错误".into());
    format!("无法执行 {name}：{reason}")
}
