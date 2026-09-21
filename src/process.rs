//! Bounded child-process execution. Output is drained to temporary files so
//! a full pipe cannot deadlock a decoder; all early exits reap the child.
use std::io::{self, Read, Seek, SeekFrom};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub(crate) fn run_bounded(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(stdout.try_clone()?));
    command.stderr(Stdio::from(stderr.try_clone()?));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn()?;
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "decoder time limit exceeded",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(1_048_576).read_to_end(&mut out)?;
    stderr.take(1_048_576).read_to_end(&mut err)?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}
