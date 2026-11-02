//! Every path the flow touches, resolved once so tests can relocate all of
//! them to a fixture root.
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub home: PathBuf,
    pub app: PathBuf,
    pub system_root: PathBuf,
    pub system_plist: PathBuf,
    pub project: PathBuf,
    pub temporary: PathBuf,
    pub system_uid: u32,
}

impl Layout {
    pub fn new(
        home: PathBuf,
        app: PathBuf,
        system_root: PathBuf,
        system_plist: PathBuf,
        project: PathBuf,
        temporary: PathBuf,
        system_uid: u32,
    ) -> Self {
        Self {
            home,
            app,
            system_root,
            system_plist,
            project,
            temporary,
            system_uid,
        }
    }
    /// The real layout for the logged-in user, given the project root.
    pub fn for_current_user(project: PathBuf, uid: u32) -> Self {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| "/".into()));
        Self::new(
            home,
            PathBuf::from("/Applications/Claude Watch Monitor.app"),
            PathBuf::from("/Library/Application Support/ClaudeWatch"),
            PathBuf::from("/Library/LaunchDaemons/io.local.claudewatch.timezone.plist"),
            project,
            PathBuf::from("/private/tmp"),
            uid,
        )
    }
    pub fn base(&self) -> PathBuf {
        self.home.join("Library/Application Support/ClaudeWatch")
    }
    pub fn trash(&self) -> PathBuf {
        self.home.join(".Trash")
    }
    pub fn agent(&self) -> PathBuf {
        self.home
            .join("Library/LaunchAgents/io.local.claudewatch.agent.plist")
    }
    pub fn updater(&self) -> PathBuf {
        self.home
            .join("Library/LaunchAgents/io.local.claudewatch.update.plist")
    }
    pub fn helper(&self) -> PathBuf {
        self.system_root.join("claude-watch-admin.sh")
    }
    /// Everything Watch owns under the user's home. Nothing else is removed.
    pub fn data_paths(&self) -> Vec<PathBuf> {
        vec![
            self.base(),
            self.home.join("Library/Preferences/io.local.watchpanel.plist"),
            self.home.join("Library/Logs/ClaudeWatch"),
            self.home.join("Library/Caches/io.local.watchpanel"),
            self.home.join("Library/WebKit/io.local.watchpanel"),
            self.home.join("Library/HTTPStorages/io.local.watchpanel"),
            self.home
                .join("Library/Saved Application State/io.local.watchpanel.savedState"),
            self.home.join("Library/Containers/io.local.watchpanel"),
            self.home
                .join("Library/Application Scripts/io.local.watchpanel"),
        ]
    }
    pub fn agent_label(&self, uid: u32) -> String {
        format!("gui/{uid}/io.local.claudewatch.agent")
    }
    pub fn updater_label(&self, uid: u32) -> String {
        format!("gui/{uid}/io.local.claudewatch.update")
    }
    pub fn helper_label(&self) -> String {
        "system/io.local.claudewatch.timezone".into()
    }
}
