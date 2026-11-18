//! Bounded, read-only repository facts for importing a local repository.
//!
//! This is not a sandbox for a concurrent, same-user writer of Git metadata.
//! The Git executable and repository filesystem must remain stable during a
//! query. Root symlink aliases are canonicalized; metadata symlinks, includes,
//! external object stores and partial clones are rejected. Only standard bare,
//! checkout and bidirectionally bound linked-worktree layouts are supported.
//! Dirty fails closed for configured external filters: disabling a clean filter
//! could otherwise misrepresent the repository's normalization semantics. Host
//! attributes/excludes are deliberately ignored; repository .gitignore remains.
//! A local custom core.attributesFile also makes dirty unknown, since ignoring
//! it could hide an ident/encoding normalization difference.

use super::{GitError, SourceGitProcess, git_command};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const MAX_OUTPUT: u64 = 1024 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// No caller-provided Git argv or revision expressions cross this interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeQuery {
    Bare,
    Head,
    Main,
    Branch,
    Dirty,
}

struct Binding {
    root: PathBuf,
    git_dir: PathBuf,
    bare: bool,
    external_filters: bool,
    external_attributes: bool,
}

fn invalid(reason: &str) -> GitError {
    GitError::Invalid(format!("safe repository probe: {reason}"))
}

// Reject known metadata escape paths before asking Git to read them. This is
// intentionally a layout check, not a recursive copy/traversal of all objects.
fn no_links(base: &Path, relative: &Path) -> Result<(), GitError> {
    let mut path = base.to_path_buf();
    for part in relative.components() {
        if !matches!(part, Component::Normal(_)) {
            return Err(invalid("invalid metadata path"));
        }
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid("symlink in repository metadata"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn small_file(path: &Path) -> Result<String, GitError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        return Err(invalid("unsupported metadata file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(invalid("metadata file exceeds limit"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("non UTF-8 metadata"))
}

fn bounded_output(
    command: Command,
    deadline: Instant,
    max_bytes: u64,
) -> Result<Vec<u8>, GitError> {
    let mut process = SourceGitProcess::spawn_command(command, deadline)?;
    process.child.stdin.take();
    let mut bytes = Vec::new();
    process
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("missing Git output"))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(invalid("output exceeds limit"));
    }
    process.finish()?;
    if Instant::now() >= deadline {
        return Err(invalid("query deadline exceeded"));
    }
    Ok(bytes)
}

// No repository discovery here: config --file --no-includes reads exactly this
// file using Git's own quoting/multiline parser. It never follows an include.
fn config_entries(path: &Path, deadline: Instant) -> Result<Vec<(String, String)>, GitError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid("configuration must be a regular file"));
    }
    let mut command = git_command(None);
    command
        .current_dir("/")
        .args(["config", "--file"])
        .arg(path)
        .args(["--no-includes", "--null", "--list"]);
    let bytes = bounded_output(command, deadline, MAX_OUTPUT)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("non UTF-8 configuration"))?;
    let mut entries = Vec::new();
    for record in text.split('\0').filter(|record| !record.is_empty()) {
        let (key, value) = record.split_once('\n').unwrap_or((record, ""));
        let key = key.to_ascii_lowercase();
        if key == "include.path" || key.starts_with("includeif.") {
            return Err(invalid("repository configuration includes are unsupported"));
        }
        if key == "extensions.partialclone"
            || (key.starts_with("remote.") && key.ends_with(".promisor") && git_true(value))
        {
            return Err(invalid("partial clones require a separate network sandbox"));
        }
        entries.push((key, value.to_string()));
    }
    Ok(entries)
}

fn git_true(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1" | ""
    )
}

// Follow only a bounded chain of loose symbolic refs before Git does so. A
// regular main ref can itself point at another, symlinked loose ref. Checking
// only HEAD/main's immediate path would miss that metadata escape.
fn check_reference_chain(git_dir: &Path, common_dir: &Path, start: &str) -> Result<(), GitError> {
    let mut reference = start.to_string();
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..8 {
        if !visited.insert(reference.clone()) {
            return Err(invalid("cyclic symbolic reference"));
        }
        no_links(git_dir, Path::new(&reference))?;
        no_links(common_dir, Path::new(&reference))?;
        let private = reference == "HEAD"
            || ["refs/bisect/", "refs/worktree/", "refs/rewritten/"]
                .iter()
                .any(|prefix| reference.starts_with(prefix));
        let path = if private { git_dir } else { common_dir }.join(&reference);
        if !path.exists() {
            return Ok(()); // Unborn or packed; packed-refs is checked separately.
        }
        let contents = small_file(&path)?;
        match contents.strip_prefix("ref:") {
            Some(target) if target.trim().starts_with("refs/") => reference = target.trim().into(),
            Some(_) => return Err(invalid("unsupported symbolic reference target")),
            None => return Ok(()),
        }
    }
    Err(invalid("symbolic reference depth exceeds limit"))
}

impl Binding {
    fn open(root: &Path, deadline: Instant) -> Result<Self, GitError> {
        if !root.is_absolute() {
            return Err(invalid("repository root must be absolute"));
        }
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(invalid("repository root must be a directory"));
        }
        no_links(&root, Path::new(".git"))?;
        let dot_git = root.join(".git");
        let (git_dir, common_dir, bare) = if dot_git.is_dir() {
            if dot_git.join("commondir").exists() {
                return Err(invalid("unexpected commondir in primary checkout"));
            }
            (dot_git.clone(), dot_git, false)
        } else if dot_git.is_file() {
            let pointer = small_file(&dot_git)?;
            let target = pointer
                .trim_end()
                .strip_prefix("gitdir: ")
                .ok_or_else(|| invalid("unsupported .git file"))?;
            let git_dir = root.join(target).canonicalize()?;
            no_links(&git_dir, Path::new("commondir"))?;
            no_links(&git_dir, Path::new("gitdir"))?;
            let common_dir = git_dir
                .join(small_file(&git_dir.join("commondir"))?.trim_end())
                .canonicalize()?;
            // A foreign gitdir pointer must not borrow another checkout's index.
            let name = git_dir
                .file_name()
                .ok_or_else(|| invalid("missing worktree identity"))?;
            no_links(&common_dir, Path::new("worktrees"))?;
            no_links(&common_dir.join("worktrees"), Path::new(name))?;
            if common_dir.join("worktrees").join(name) != git_dir
                || Path::new(small_file(&git_dir.join("gitdir"))?.trim_end()).canonicalize()?
                    != dot_git
            {
                return Err(invalid("linked worktree binding does not match root"));
            }
            (git_dir, common_dir, false)
        } else {
            (root.clone(), root.clone(), true)
        };
        if common_dir.join("commondir").exists() {
            return Err(invalid("nested common directories are unsupported"));
        }
        for base in [&git_dir, &common_dir] {
            for path in [
                "config",
                "config.worktree",
                "HEAD",
                "index",
                "packed-refs",
                "shallow",
                "refs/heads/main",
                "objects",
                "objects/info",
                "objects/pack",
                "info/exclude",
                "info/attributes",
                "objects/info/alternates",
                "objects/info/http-alternates",
            ] {
                no_links(base, Path::new(path))?;
            }
        }
        if !common_dir.join("objects").is_dir() || !git_dir.join("HEAD").is_file() {
            return Err(invalid("root is not a supported Git repository"));
        }
        for path in ["objects/info/alternates", "objects/info/http-alternates"] {
            let path = common_dir.join(path);
            if path.exists() && !small_file(&path)?.trim().is_empty() {
                return Err(invalid("external object stores are unsupported"));
            }
        }
        check_reference_chain(&git_dir, &common_dir, "HEAD")?;
        check_reference_chain(&git_dir, &common_dir, "refs/heads/main")?;
        let mut entries = config_entries(&common_dir.join("config"), deadline)?;
        if entries
            .iter()
            .any(|(key, value)| key == "extensions.worktreeconfig" && git_true(value))
        {
            entries.extend(config_entries(&git_dir.join("config.worktree"), deadline)?);
        }
        if bare
            && !entries
                .iter()
                .rev()
                .find(|(key, _)| key == "core.bare")
                .is_some_and(|(_, value)| git_true(value))
        {
            return Err(invalid("a bare root must declare core.bare=true"));
        }
        let external_filters = entries.iter().any(|(key, value)| {
            key.starts_with("filter.")
                && (key.ends_with(".clean") || key.ends_with(".process"))
                && !value.is_empty()
        });
        let external_attributes = entries.iter().any(|(key, value)| {
            key == "core.attributesfile" && !value.is_empty() && value != "/dev/null"
        });
        Ok(Self {
            root,
            git_dir,
            bare,
            external_filters,
            external_attributes,
        })
    }
}

/// Returns the existing probe fact representation: `true`/`false`, SHA,
/// branch, or porcelain status. Missing HEAD/main/detached branch are errors;
/// the HTTP read model may represent those facts as null. Bare dirty is empty.
/// A failure is never an assertion that a worktree is clean.
pub fn read(root: &Path, query: ProbeQuery) -> Result<String, GitError> {
    if !cfg!(unix) {
        return Err(invalid("bounded process-group probes require Unix"));
    }
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let binding = Binding::open(root, deadline)?;
    if query == ProbeQuery::Dirty {
        if binding.bare {
            return Ok(String::new());
        }
        if binding.external_filters {
            return Err(invalid(
                "dirty is unknown with external clean/process filters",
            ));
        }
        if binding.external_attributes {
            return Err(invalid("dirty is unknown with a custom attributes file"));
        }
    }
    let mut command = git_command(None);
    command
        .arg("--no-optional-locks")
        .arg("--no-replace-objects")
        .arg("--git-dir")
        .arg(&binding.git_dir)
        .arg("-C")
        .arg(&binding.root)
        .args([
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "core.untrackedCache=false",
        ])
        .env("GIT_OPTIONAL_LOCKS", "0");
    if !binding.bare {
        command.arg("--work-tree").arg(&binding.root);
    }
    let args: &[&str] = match query {
        ProbeQuery::Bare => &["rev-parse", "--is-bare-repository"],
        ProbeQuery::Head => &["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
        ProbeQuery::Main => &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            "refs/heads/main^{commit}",
        ],
        ProbeQuery::Branch => &["symbolic-ref", "--quiet", "--short", "HEAD"],
        ProbeQuery::Dirty => &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=all",
            "--no-renames",
        ],
    };
    command.args(args);
    let bytes = bounded_output(command, deadline, MAX_OUTPUT)?;
    let result = std::str::from_utf8(&bytes).map_err(|_| invalid("non UTF-8 Git output"))?;
    Ok(result.trim().to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn output_limit_returns_error_and_reaps_the_owned_process() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '123456789'; sleep 10"]);
        let start = Instant::now();
        assert!(bounded_output(command, start + Duration::from_secs(2), 8).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn deadline_kills_the_owned_process_group() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 10"]);
        let start = Instant::now();
        assert!(bounded_output(command, start + Duration::from_millis(100), 8).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
