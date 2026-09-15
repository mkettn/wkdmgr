//! Best-effort hook runner. On successful key add/remove, every
//! executable in the corresponding `<hooks_dir>/on_key_add/` or
//! `<hooks_dir>/on_key_remove/` directory is run, in filename sort
//! order, as `script <email> <domain>`. A failing or hanging hook never
//! fails or blocks the underlying operation: hooks run strictly after
//! the operation has already succeeded and been persisted.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Run every hook in `<hooks_dir>/on_key_add/`, piping the minimized key
/// bytes to each script's stdin.
pub async fn run_on_key_add(
    hooks_dir: &Path,
    address: &str,
    domain: &str,
    key_data: &[u8],
    timeout: Duration,
) {
    run_hooks(
        hooks_dir,
        "on_key_add",
        address,
        domain,
        Some(key_data),
        timeout,
    )
    .await;
}

/// Run every hook in `<hooks_dir>/on_key_remove/`. No stdin payload: the
/// key is already gone from the DB by the time these run.
pub async fn run_on_key_remove(hooks_dir: &Path, address: &str, domain: &str, timeout: Duration) {
    run_hooks(hooks_dir, "on_key_remove", address, domain, None, timeout).await;
}

async fn run_hooks(
    hooks_dir: &Path,
    subdir: &str,
    address: &str,
    domain: &str,
    stdin_payload: Option<&[u8]>,
    timeout: Duration,
) {
    let dir = hooks_dir.join(subdir);
    let scripts = match list_executable_scripts(&dir).await {
        Ok(scripts) => scripts,
        Err(e) => {
            tracing::debug!("hooks dir {} not usable: {e}", dir.display());
            return;
        }
    };

    for script in scripts {
        run_one_hook(&script, address, domain, stdin_payload, timeout).await;
    }
}

async fn list_executable_scripts(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut scripts = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if is_executable_file(&path).await {
            scripts.push(path);
        }
    }
    scripts.sort();
    Ok(scripts)
}

async fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match tokio::fs::metadata(path).await {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

async fn run_one_hook(
    script: &Path,
    address: &str,
    domain: &str,
    stdin_payload: Option<&[u8]>,
    timeout: Duration,
) {
    let mut cmd = Command::new(script);
    cmd.arg(address).arg(domain);
    cmd.stdin(if stdin_payload.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("failed to spawn hook {}: {e}", script.display());
            return;
        }
    };

    if let Some(payload) = stdin_payload {
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(payload).await {
                tracing::warn!("failed writing stdin to hook {}: {e}", script.display());
            }
            // Drop to close the pipe so the script sees EOF.
            drop(stdin);
        }
    }

    let wait_and_collect = async {
        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let (status, _, _) = tokio::join!(
            child.wait(),
            async {
                if let Some(s) = stdout_pipe.as_mut() {
                    let _ = s.read_to_end(&mut stdout_buf).await;
                }
            },
            async {
                if let Some(s) = stderr_pipe.as_mut() {
                    let _ = s.read_to_end(&mut stderr_buf).await;
                }
            },
        );
        (status, stdout_buf, stderr_buf)
    };

    match tokio::time::timeout(timeout, wait_and_collect).await {
        Ok((Ok(status), stdout, stderr)) => {
            if !status.success() {
                tracing::warn!(
                    "hook {} exited with {status}: stdout={:?} stderr={:?}",
                    script.display(),
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr),
                );
            } else {
                tracing::debug!("hook {} succeeded", script.display());
            }
        }
        Ok((Err(e), _, _)) => {
            tracing::warn!("hook {} failed to run: {e}", script.display());
        }
        Err(_) => {
            tracing::warn!(
                "hook {} timed out after {timeout:?}; killing",
                script.display()
            );
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn write_script(dir: &Path, name: &str, contents: &str) {
        let path = dir.join(name);
        tokio::fs::write(&path, contents).await.unwrap();
        let mut perms = tokio::fs::metadata(&path).await.unwrap().permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&path, perms).await.unwrap();
    }

    #[tokio::test]
    async fn runs_scripts_in_sort_order_with_stdin_payload() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks.d");
        let add_dir = hooks_dir.join("on_key_add");
        tokio::fs::create_dir_all(&add_dir).await.unwrap();

        let out_file = dir.path().join("order.txt");
        write_script(
            &add_dir,
            "10-second.sh",
            &format!(
                "#!/bin/sh\necho \"2 $1 $2\" >> {}\ncat >/dev/null\n",
                out_file.display()
            ),
        )
        .await;
        write_script(
            &add_dir,
            "01-first.sh",
            &format!(
                "#!/bin/sh\necho \"1 $1 $2\" >> {}\ncat >/dev/null\n",
                out_file.display()
            ),
        )
        .await;

        run_on_key_add(
            &hooks_dir,
            "alice@example.com",
            "example.com",
            b"key bytes",
            Duration::from_secs(5),
        )
        .await;

        let contents = tokio::fs::read_to_string(&out_file).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(
            lines,
            vec![
                "1 alice@example.com example.com",
                "2 alice@example.com example.com"
            ]
        );
    }

    #[tokio::test]
    async fn missing_hooks_dir_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join("does-not-exist");
        run_on_key_remove(
            &hooks_dir,
            "alice@example.com",
            "example.com",
            Duration::from_secs(1),
        )
        .await;
        // No panic == pass.
    }

    #[tokio::test]
    async fn failing_hook_does_not_panic_or_propagate() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks.d");
        let remove_dir = hooks_dir.join("on_key_remove");
        tokio::fs::create_dir_all(&remove_dir).await.unwrap();
        write_script(&remove_dir, "01-fail.sh", "#!/bin/sh\nexit 1\n").await;

        run_on_key_remove(
            &hooks_dir,
            "alice@example.com",
            "example.com",
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn hanging_hook_is_killed_after_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks.d");
        let add_dir = hooks_dir.join("on_key_add");
        tokio::fs::create_dir_all(&add_dir).await.unwrap();
        write_script(&add_dir, "01-hang.sh", "#!/bin/sh\nsleep 60\n").await;

        let start = std::time::Instant::now();
        run_on_key_add(
            &hooks_dir,
            "alice@example.com",
            "example.com",
            b"key bytes",
            Duration::from_millis(200),
        )
        .await;
        assert!(start.elapsed() < Duration::from_secs(30));
    }
}
