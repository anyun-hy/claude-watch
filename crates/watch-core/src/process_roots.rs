//! AI roots require an observed executable/bundle or the actual interpreter entrypoint.
use crate::policy::PolicyCatalog;
use crate::processes::{Identity, Kind, MatchReason, Provider};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

/// The desktop bundle identifier one provider's own app lives under.
fn provider_bundle_id(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "com.anthropic.claudefordesktop",
        Provider::Codex | Provider::Openai => "com.openai.codex",
        Provider::Chatgpt => "com.openai.chat",
    }
}

/// The install prefix one provider's own app runs from, used when a process
/// carries no bundle id but its executable path still names the app.
fn provider_app_prefix(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "/Applications/Claude.app/Contents/",
        Provider::Codex | Provider::Openai => "/Applications/Codex.app/Contents/",
        Provider::Chatgpt => "/Applications/ChatGPT.app/Contents/",
    }
}

/// Every desktop bundle the supervised target's policy family covers, and the
/// matching install prefixes. A family supervises its providers as one
/// service: ChatGPT and Codex enter and leave together, exactly as the policy
/// table declares them. A target outside every family supervises nothing.
pub fn family_desktop_scopes(provider: Provider) -> (Vec<&'static str>, Vec<&'static str>) {
    let Some(family) = PolicyCatalog::family_for(provider) else {
        return (Vec::new(), Vec::new());
    };
    let mut ids: Vec<&'static str> =
        family.providers.iter().map(|p| provider_bundle_id(*p)).collect();
    let mut prefixes: Vec<&'static str> =
        family.providers.iter().map(|p| provider_app_prefix(*p)).collect();
    ids.sort_unstable();
    ids.dedup();
    prefixes.sort_unstable();
    prefixes.dedup();
    (ids, prefixes)
}

pub struct RootEvidence<'a> {
    pub identity: &'a Identity,
    pub bundle_path: Option<&'a str>,
    pub bundle_id: Option<&'a str>,
    pub arguments: Option<&'a [String]>,
    pub cwd: Option<&'a str>,
}
#[derive(Default)]
pub struct TrustedCliPaths {
    pub claude: BTreeSet<String>,
    pub codex: BTreeSet<String>,
    /// Runtime-verified installations. None retains the legacy pure classifier
    /// API; production discovery supplies Some, including an empty catalog.
    pub desktop_catalog: Option<Vec<(PathBuf, String, PathBuf)>>,
    pub pending_desktops:Vec<(PathBuf,String)>,
    pub exact_cli_catalog: bool,
    pub cli_reasons: BTreeMap<String, MatchReason>,
}
/// Supported installation aliases. Capture and inventory parity checks consume
/// this list; an arbitrary same-named executable is not an AI root.
pub fn cli_aliases(home: &Path) -> Vec<(PathBuf, bool)> {
    vec![
        (home.join(".local/bin/claude"), true),
        (home.join(".claude/local/claude"), true),
        ("/opt/homebrew/bin/claude".into(), true),
        ("/usr/local/bin/claude".into(), true),
        (home.join(".local/bin/codex"), false),
        ("/opt/homebrew/bin/codex".into(), false),
        ("/usr/local/bin/codex".into(), false),
    ]
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    Root(Kind),
    NeedArguments,
    NotTarget,
}
fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
}
fn claude_script(path: &str) -> bool {
    path.ends_with("/node_modules/@anthropic-ai/claude-code/cli.js")
}
fn codex_script(path: &str) -> bool {
    path.ends_with("/node_modules/@openai/codex/bin/codex.js")
}
pub fn lexical_path(value: &str, cwd: Option<&str>) -> Option<PathBuf> {
    let value = Path::new(value);
    let path = if value.is_absolute() {
        value.into()
    } else {
        Path::new(cwd.filter(|s| s.starts_with('/'))?).join(value)
    };
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir => normalized.push("/"),
            Component::Normal(p) => normalized.push(p),
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    normalized.is_absolute().then_some(normalized)
}
fn node_entry(arguments: &[String]) -> Option<&str> {
    if !["node", "nodejs", "bun"].contains(&basename(arguments.first()?)) {
        return None;
    }
    let mut index = 1;
    loop {
        let token = arguments.get(index)?;
        index += 1;
        if token == "--" {
            return arguments.get(index).map(String::as_str);
        }
        if [
            "--no-warnings",
            "--enable-source-maps",
            "--watch-preserve-output",
        ]
        .contains(&token.as_str())
            || ["--experimental-", "--trace-", "--disable-warning="]
                .iter()
                .any(|p| token.starts_with(p))
        {
            continue;
        }
        if ["--require", "--import", "--conditions", "--loader"].contains(&token.as_str()) {
            arguments.get(index)?;
            index += 1;
            continue;
        }
        if ["--require=", "--import=", "--conditions=", "--loader="]
            .iter()
            .any(|p| token.starts_with(p))
        {
            continue;
        }
        return (!token.starts_with('-')).then_some(token);
    }
}
pub fn node_script_entry(arguments:&[String],cwd:Option<&str>)->Option<PathBuf> {
    lexical_path(node_entry(arguments)?,cwd)
}
pub fn desktop_kind(bundle: &str, id: &str, main: bool) -> Option<Kind> {
    let name = basename(bundle);
    match (id, name, main) {
        ("com.anthropic.claudefordesktop", _, true) => Some(Kind::ClaudeMain),
        ("com.anthropic.claudefordesktop", _, false) => Some(Kind::ClaudeHelper),
        ("com.openai.codex", "ChatGPT.app", true) => Some(Kind::OpenaiMain),
        ("com.openai.codex", "ChatGPT.app", false) => Some(Kind::OpenaiHelper),
        ("com.openai.codex", _, true) => Some(Kind::CodexMain),
        ("com.openai.codex", _, false) => Some(Kind::CodexHelper),
        ("com.openai.chat", _, true) => Some(Kind::ChatgptMain),
        ("com.openai.chat", _, false) => Some(Kind::ChatgptHelper),
        _ => None,
    }
}

pub fn cli_kind(path: &str, home: &Path, trusted: &TrustedCliPaths) -> Option<Kind> {
    cli_kind_with_reason(path, home, trusted).map(|(kind, _)| kind)
}
fn cli_kind_with_reason(path: &str, home: &Path, trusted: &TrustedCliPaths) -> Option<(Kind, MatchReason)> {
    let exact_reason=trusted.cli_reasons.get(path).copied().unwrap_or(MatchReason::SupportedCliAlias);
    if trusted.claude.contains(path) { return Some((Kind::ClaudeCode, exact_reason)); }
    if trusted.codex.contains(path) { return Some((Kind::CodexCli, exact_reason)); }
    if trusted.exact_cli_catalog { return None; }
    let home = home.to_string_lossy();
    if path.starts_with(&format!("{home}/.local/share/claude/versions/")) || claude_script(path) {
        return Some((Kind::ClaudeCode, MatchReason::KnownCliLayout));
    }
    if trusted.codex.contains(path) { return Some((Kind::CodexCli, MatchReason::SupportedCliAlias)); }
    if (path.contains("/Caskroom/codex/") && path.ends_with("/bin/codex"))
        || codex_script(path) || (path.contains("/node_modules/@openai/codex/") && path.ends_with("/codex")) {
        return Some((Kind::CodexCli, MatchReason::KnownCliLayout));
    }
    None
}

pub fn managed_codex_app_server(path: &str, home: &Path) -> bool {
    let Some(path) = lexical_path(path, None) else {
        return false;
    };
    let Some(home) = lexical_path(&home.to_string_lossy(), None) else {
        return false;
    };
    let base = home.join(".codex/packages/app-server-daemon/releases");
    let Ok(relative) = path.strip_prefix(base) else {
        return false;
    };
    let parts: Vec<_> = relative.components().collect();
    matches!(parts.as_slice(), [Component::Normal(_), Component::Normal(bin), Component::Normal(executable)] if *bin == "bin" && *executable == "codex")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootClassification {
    pub classification: Classification,
    pub reason: Option<MatchReason>,
}
impl RootClassification {
    fn root(kind: Kind, reason: MatchReason) -> Self { Self { classification: Classification::Root(kind), reason: Some(reason) } }
    fn other(classification: Classification) -> Self { Self { classification, reason: None } }
}

pub fn classify(
    evidence: RootEvidence<'_>, home: &Path, trusted: &TrustedCliPaths,
    resolve: impl Fn(&Path) -> Option<PathBuf>,
) -> Classification {
    classify_with_evidence(evidence, home, trusted, resolve).classification
}

pub fn classify_with_evidence(
    evidence: RootEvidence<'_>,
    home: &Path,
    trusted: &TrustedCliPaths,
    resolve: impl Fn(&Path) -> Option<PathBuf>,
) -> RootClassification {
    use Classification::*;
    let identity = evidence.identity;
    if !identity.valid() {
        return RootClassification::other(NotTarget);
    }
    let path = &identity.executable;
    if managed_codex_app_server(path, home) {
        let Some(args) = evidence.arguments else {
            return RootClassification::other(NeedArguments);
        };
        return if args.first().is_some_and(|arg| basename(arg) == "codex")
            && args.get(1).is_some_and(|arg| arg == "app-server")
            && (args.get(2).is_some_and(|arg| arg == "daemon")
                || (args.get(2).is_some_and(|arg| arg == "--listen")
                    && args
                        .get(3)
                        .is_some_and(|arg| !arg.is_empty() && !arg.starts_with('-'))))
        {
            RootClassification::root(Kind::CodexCli, MatchReason::ManagedAppServer)
        } else {
            RootClassification::other(NotTarget)
        };
    }
    if let Some((kind, reason)) = cli_kind_with_reason(path, home, trusted) {
        return RootClassification::root(kind, reason);
    }
    if let Some((prefix, _)) = path.split_once(".app/Contents/") {
        let bundle = format!("{prefix}.app");
        let verified = trusted.desktop_catalog.as_ref().and_then(|catalog|catalog.iter().find(|(root,_,_)|
            root == Path::new(&bundle)));
        if verified.is_none() {
            if let Some((root,id))=trusted.pending_desktops.iter().find(|(root,id)|root==Path::new(&bundle) && evidence.bundle_id.is_none_or(|actual|actual==id)) {
                if let Some(kind)=desktop_kind(root.to_string_lossy().as_ref(),id,path.starts_with(&format!("{bundle}/Contents/MacOS/"))) {
                    return RootClassification::root(kind,MatchReason::InstallationPending);
                }
            }
        }
        if verified.is_some() || (trusted.desktop_catalog.is_none() && evidence.bundle_path == Some(bundle.as_str())) {
            let id = verified.map(|(_,id,_)|id.as_str()).or(evidence.bundle_id).unwrap_or("");
            if ["com.openai.codex", "com.openai.chat"].contains(&id)
                && (path.ends_with("/Resources/codex")
                    || path.contains("/Resources/codex-cli/")
                    || path.ends_with("/CodexCLI.app/Contents/MacOS/codex"))
            {
                return RootClassification::root(Kind::CodexCli, MatchReason::VerifiedBundleComponent);
            }
            let main = verified.map(|(_,_,exe)|Path::new(path)==exe).unwrap_or_else(||path.starts_with(&format!("{bundle}/Contents/MacOS/")));
            let kind = desktop_kind(&bundle, id, main);
            if let Some(kind) = kind {
                return RootClassification::root(kind, MatchReason::VerifiedBundle);
            }
        }
    }
    if ["node", "nodejs", "bun"].contains(&basename(path)) {
        let Some(arguments) = evidence.arguments else {
            return RootClassification::other(NeedArguments);
        };
        let Some(script) = node_entry(arguments) else {
            return RootClassification::other(NotTarget);
        };
        let Some(script) = lexical_path(script, evidence.cwd) else {
            return RootClassification::other(NotTarget);
        };
        let script = resolve(&script).unwrap_or(script);
        let script = script.to_string_lossy();
        if (trusted.exact_cli_catalog && trusted.claude.contains(script.as_ref())) || (!trusted.exact_cli_catalog && claude_script(&script)) {
            return RootClassification::root(Kind::ClaudeCode, MatchReason::ScriptEntry);
        }
        if (trusted.exact_cli_catalog && trusted.codex.contains(script.as_ref())) || (!trusted.exact_cli_catalog && codex_script(&script)) {
            return RootClassification::root(Kind::CodexCli, MatchReason::ScriptEntry);
        }
    }
    RootClassification::other(NotTarget)
}
