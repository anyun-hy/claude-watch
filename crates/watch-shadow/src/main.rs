#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("claude-watch-shadow --shadow\nRead bounded JSON lines from stdin; emit non-authoritative comparisons.\nNo network, file, account, system-setting or application-control operations.");
        return ExitCode::SUCCESS;
    }
    if args != ["--shadow"] {
        eprintln!("usage: claude-watch-shadow --shadow");
        return ExitCode::from(64);
    }
    match claude_watch_shadow::run(io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("shadow_io_error");
            ExitCode::from(74)
        }
    }
}
