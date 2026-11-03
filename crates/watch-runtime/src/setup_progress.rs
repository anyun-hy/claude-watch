//! Optional, status-only progress on a child process's stderr. These phases
//! carry no address, credentials, authority or arbitrary upstream messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    VerifyEgress,
    RequestAdministrator,
    ApplySettings,
    VerifySettings,
    SaveBaseline,
    RestoreSettings,
    CollectEvidence,
    VerifyLaunchConditions,
    BindSession,
    OpenApplication,
}
impl Phase {
    pub fn code(self) -> &'static str {
        match self {
            Self::VerifyEgress => "verify_egress",
            Self::RequestAdministrator => "request_administrator",
            Self::ApplySettings => "apply_settings",
            Self::VerifySettings => "verify_settings",
            Self::SaveBaseline => "save_baseline",
            Self::RestoreSettings => "restore_settings",
            Self::CollectEvidence => "collect_evidence",
            Self::VerifyLaunchConditions => "verify_launch_conditions",
            Self::BindSession => "bind_session",
            Self::OpenApplication => "open_application",
        }
    }
}
pub fn emit(phase: Phase) {
    if std::env::var("CW_SETUP_PROGRESS").as_deref() == Ok("1") {
        eprintln!("CW_SETUP_PROGRESS:{}", phase.code());
    }
}
