use anyhow::{Context, anyhow};
use futures::StreamExt;
use git2::{BranchType, Repository};
use sha2::Digest;
use std::{env, fs::File, path::Path, path::PathBuf};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    task,
};

/// Manage the download of migration dumps
#[derive(Debug)]
pub struct Migration {
    base: PathBuf,
    branch: String,

    region: String,
    bucket: String,
}

impl Migration {
    /// Create a new instance, detecting paths and the branch
    pub fn new() -> anyhow::Result<Self> {
        // base for storing dumps, does not include the branch name
        let base = env::var_os("TRUSTIFY_MIGRATION_DUMPS")
            .map(PathBuf::from)
            .or_else(|| {
                env::current_dir()
                    .ok()
                    .map(|path| path.join(".trustify").join("migration-dumps"))
            })
            .ok_or_else(|| anyhow!("unable to determine migration dumps directory"))?;

        log::info!("Using migration base: '{}'", base.display());

        // get the base of the source code

        let cwd: PathBuf = match option_env!("CARGO_MANIFEST_DIR") {
            Some(cwd) => cwd.into(),
            None => env::current_dir().context("unable to determine current directory")?,
        };

        // evaluate the branch

        let branch = env::var("TRUSTIFY_MIGRATION_BRANCH")
            .or_else(|_| current_branch(cwd))
            .context("unable to determine branch, consider using 'TRUSTIFY_MIGRATION_BRANCH'")?;

        log::info!("Using migration for branch: '{branch}'");

        // region and bucket

        let region = env::var("TRUSTIFY_S3_AWS_REGION").unwrap_or_else(|_| "eu-west-1".to_string());
        let bucket = env::var("TRUSTIFY_S3_AWS_BUCKET")
            .unwrap_or_else(|_| "guacsec-migration-dumps".to_string());

        // done

        Ok(Self {
            base,
            branch,
            region,
            bucket,
        })
    }

    /// Provide the base dump path, for this branch.
    ///
    /// This may include downloading content from S3.
    pub async fn provide(&self, id: &str) -> anyhow::Result<PathBuf> {
        let base = self.base.join(&self.branch).join(id);

        log::info!("branch base path: '{}'", base.display());

        fs::create_dir_all(&base).await?;

        // lock file, we can't lock directories cross-platform

        let lock = task::spawn_blocking({
            let base = base.clone();
            move || {
                let lock = File::create(base.join(".lock"))?;
                // the existence of the lock file means nothing, only the lock on it
                lock.lock()?;

                Ok::<_, anyhow::Error>(lock)
            }
        })
        .await??;

        // holding the lock

        let files = ["dump.sql.xz", "dump.tar"];

        if files.iter().any(|file| !base.join(file).exists()) {
            let client = reqwest::Client::new();
            download_artifacts(
                client,
                &base,
                &self.bucket,
                &self.region,
                &self.branch,
                id,
                files,
            )
            .await?
        } else {
            log::debug!("dump files already exist");
        }

        //  validate checksums

        validate_checksums(&base, files).await?;

        // unlock

        lock.unlock()?;

        Ok(base)
    }
}

/// Discover the base branch name
///
/// This should be either a `main` or `release/*` branch. In cases of a branch for a PR, it should
/// be the parent branch forked from.
fn current_branch(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let path = path.as_ref();

    // check if this branch name is relevant
    fn is_relevant(name: &str) -> bool {
        name == "main" || name.starts_with("release/")
    }

    log::info!("Discovering the current branch at {}", path.display());
    let repo = Repository::discover(path)?;
    let head = repo.head()?;

    // Try to get branch shorthand (may be "HEAD" or commit hash in detached state)
    let branch_shorthand = head
        .shorthand()
        .filter(|s| *s != "HEAD")
        .map(|s| s.to_string());
    let head_commit = head.peel_to_commit()?;

    // Early return if we're on main or release/* or GitHub merge queue

    if let Some(ref name) = branch_shorthand {
        if is_relevant(name) {
            log::info!("Is relevant base: {name}");
            return Ok(name.clone());
        }

        // GitHub merge queue branches look like: gh-readonly-queue/<base>/<id>

        if let Some(name) = is_merge_queue(name) {
            log::info!("Is merge queue for base: {name}");
            return Ok(name);
        }
    }

    // Collect candidate parent branches: local branches named `main` or starting with `release/`.

    let mut candidates = Vec::new();
    for branch_res in repo.branches(Some(BranchType::Local))? {
        let (branch, _branch_type) = branch_res?;
        let Some(name) = branch.name()? else {
            continue;
        };

        if is_relevant(name) {
            candidates.push(branch);
        }
    }

    // Try to find if HEAD matches any branch tip exactly

    for candidate in &candidates {
        let Ok(commit) = candidate.get().peel_to_commit() else {
            continue;
        };

        if commit.id() == head_commit.id() {
            return Ok(candidate.name()?.unwrap_or("unknown").to_string());
        }
    }

    // Find a candidate whose tip shares the most recent common ancestor with HEAD.

    let mut best_branch: Option<String> = None;
    let mut best_time: i64 = i64::MIN;

    for candidate in candidates {
        let Ok(candidate_commit) = candidate.get().peel_to_commit() else {
            continue;
        };

        let Ok(ancestor_oid) = repo.merge_base(head_commit.id(), candidate_commit.id()) else {
            continue;
        };

        let Ok(ancestor_commit) = repo.find_commit(ancestor_oid) else {
            continue;
        };

        let t = ancestor_commit.time().seconds();
        if t > best_time {
            best_time = t;
            best_branch = candidate.name().ok().flatten().map(String::from);
        }
    }

    // Prefer the best inferred branch if we found one.

    if let Some(b) = best_branch {
        return Ok(b);
    }

    // Fallback: return branch shorthand if meaningful, otherwise "main"

    Ok(branch_shorthand.unwrap_or_else(|| "main".to_string()))
}

/// Check if the branch name is a merge queue name and return the base branch
fn is_merge_queue(name: &str) -> Option<String> {
    if let Some(stripped) = name.strip_prefix("gh-readonly-queue/") {
        let parts: Vec<_> = stripped.split('/').collect();
        let parent = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };
        Some(parent)
    } else {
        None
    }
}

/// validate checksums of `<file>` by validating its SHA256 against the value from `<file>.sha256`
async fn validate_checksums(
    base: impl AsRef<Path>,
    files: impl IntoIterator<Item = impl AsRef<str>>,
) -> anyhow::Result<()> {
    let base = base.as_ref();

    for file in files {
        let file = file.as_ref();

        // open content file

        let mut content = BufReader::new(fs::File::open(base.join(file)).await?);
        let mut buffer = [0u8; 8192];
        let mut hasher = sha2::Sha256::new();

        // process file content

        loop {
            let n = content.read(&mut buffer).await?;
            if n == 0 {
                // zero means EOF
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let calculated = format!("{:x}", hasher.finalize());

        // read digest file

        let digest = base.join(format!("{file}.sha256"));
        let digest = fs::File::open(digest).await?;
        let mut lines = BufReader::new(digest).lines();
        let expected = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("SHA256 file is empty"))?
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("missing digest"))?
            .to_lowercase();

        // compare

        anyhow::ensure!(
            calculated == expected,
            "Checksum mismatch for {file}: expected {expected}, got {calculated}"
        );
    }

    Ok(())
}

/// just download artifacts (and their digest files) from the dump bucket
async fn download_artifacts(
    client: reqwest::Client,
    base: impl AsRef<Path>,
    bucket: &str,
    region: &str,
    branch: &str,
    commit: &str,
    files: impl IntoIterator<Item = impl AsRef<str>>,
) -> anyhow::Result<()> {
    let base = base.as_ref();

    for file in files.into_iter().flat_map(|file| {
        let file = file.as_ref();
        vec![file.to_string(), format!("{file}.sha256")]
    }) {
        let url = format!("https://{bucket}.s3.{region}.amazonaws.com/{branch}/{commit}/{file}",);

        log::info!("downloading file: '{url}'");

        let mut dest = fs::File::create(base.join(file)).await?;
        let mut stream = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            io::copy(&mut chunk.as_ref(), &mut dest).await?;
        }

        dest.shutdown().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks a merge queue branch with multiple middle parts; should return all parts except the last.
    #[test]
    fn merge_queue_with_multiple_parts() {
        assert_eq!(
            is_merge_queue("gh-readonly-queue/main/bar/pr"),
            Some("main/bar".to_string())
        );
    }

    /// Checks a merge queue branch that only has the base branch; should return an empty string.
    #[test]
    fn merge_queue_with_only_base_branch() {
        assert_eq!(
            is_merge_queue("gh-readonly-queue/main"),
            Some("".to_string())
        );
    }

    /// Checks a merge queue branch with exactly two parts; should return the first part.
    #[test]
    fn merge_queue_with_two_parts() {
        assert_eq!(
            is_merge_queue("gh-readonly-queue/main/pr"),
            Some("main".to_string())
        );
    }

    /// Checks a non-merge-queue branch; should return None.
    #[test]
    fn non_merge_queue_branch() {
        assert_eq!(is_merge_queue("feature/new-feature"), None);
    }

    /// Checks an empty string as input; should return None.
    #[test]
    fn empty_string() {
        assert_eq!(is_merge_queue(""), None);
    }

    /// Checks a branch name that is only the merge queue prefix; should return an empty string.
    #[test]
    fn prefix_only() {
        assert_eq!(is_merge_queue("gh-readonly-queue/"), Some("".to_string()));
    }
}
