use crate::runner::common::walker::WorkingDirectory;
use anyhow::anyhow;
use git2::{
    Cred, ErrorClass, ErrorCode, FetchOptions, RemoteCallbacks, Repository, ResetType,
    build::RepoBuilder,
};
use std::{
    borrow::Cow,
    collections::HashSet,
    convert::Infallible,
    env,
    fmt::{Debug, Display},
    fs::remove_dir_all,
    path::{Path, PathBuf},
};
use tracing::{info_span, instrument};
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, thiserror::Error)]
pub enum HandlerError<T> {
    #[error(transparent)]
    Processing(T),
    #[error("operation canceled")]
    Canceled,
}

pub trait Handler: Send + 'static {
    type Error: Display + Debug;

    fn process(&self, path: &Path, relative_path: &Path) -> Result<(), HandlerError<Self::Error>>;
    fn is_canceled(&self) -> bool;
}

impl Handler for () {
    type Error = Infallible;

    fn process(&self, _: &Path, _: &Path) -> Result<(), HandlerError<Self::Error>> {
        Ok(())
    }
    fn is_canceled(&self) -> bool {
        false
    }
}

pub struct GitWalker<H, T, P>
where
    T: WorkingDirectory + Send + 'static,
    H: Handler,
    P: Progress,
{
    /// The git source to clone from
    pub source: String,

    /// The branch to check out
    pub branch: Option<String>,

    /// A path inside the cloned repository to start searching for files
    pub path: Option<String>,

    /// Continuation token
    pub continuation: Continuation,

    /// A working directory
    pub working_dir: T,

    /// The handler
    pub handler: H,

    pub progress: P,

    /// Fetch depth, <=0 means get everything
    pub depth: i32,
}

impl<H> GitWalker<H, (), ()>
where
    H: Handler,
{
    /// Create a new GitWalker for a given repo and handler. By
    /// default, a "shallow clone" (depth=1) of the repo will be
    /// walked.
    pub fn new(source: impl Into<String>, handler: H) -> Self {
        Self {
            source: source.into(),
            branch: None,
            path: None,
            continuation: Default::default(),
            working_dir: (),
            handler,
            progress: (),
            depth: 1, // shallow clone, by default
        }
    }
}

impl<H, T, P> GitWalker<H, T, P>
where
    H: Handler,
    T: WorkingDirectory + Send + 'static,
    P: Progress + Send + 'static,
{
    pub fn handler<U: Handler>(self, handler: U) -> GitWalker<U, T, P> {
        GitWalker {
            source: self.source,
            branch: self.branch,
            path: self.path,
            continuation: self.continuation,
            working_dir: self.working_dir,
            handler,
            progress: self.progress,
            depth: self.depth,
        }
    }

    pub fn progress<U: Progress>(self, progress: U) -> GitWalker<H, T, U> {
        GitWalker {
            source: self.source,
            branch: self.branch,
            path: self.path,
            continuation: self.continuation,
            working_dir: self.working_dir,
            handler: self.handler,
            progress,
            depth: self.depth,
        }
    }

    /// Set a working directory.
    ///
    /// The data in this working directory will be re-used. However, it must be specific to the
    /// source used. It is not possible to re-use the same working-directory for multiple different
    /// sources.
    ///
    /// It may also be `()`, which uses a temporary working directory. However, this will result in
    /// the walker cloning the full repository with ever run, which might be quite expensive.
    pub fn working_dir<U: WorkingDirectory + Send + 'static>(
        self,
        working_dir: U,
    ) -> GitWalker<H, U, P> {
        GitWalker {
            source: self.source,
            branch: self.branch,
            path: self.path,
            continuation: self.continuation,
            working_dir,
            handler: self.handler,
            progress: self.progress,
            depth: self.depth,
        }
    }

    pub fn branch(mut self, branch: Option<impl Into<String>>) -> Self {
        self.branch = branch.map(|s| s.into());
        self
    }

    pub fn path(mut self, path: Option<impl Into<String>>) -> Self {
        self.path = path.map(|s| s.into());
        self
    }

    pub fn depth(mut self, depth: i32) -> Self {
        self.depth = depth;
        self
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: Continuation) -> Self {
        self.continuation = continuation;
        self
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<Continuation, Error> {
        tokio::task::spawn_blocking(|| self.run_sync()).await?
    }

    /// Sync version, as all git functions are sync
    #[instrument(skip(self), err)]
    fn run_sync(self) -> Result<Continuation, Error> {
        log::debug!("Starting run for: {}", self.source);

        let working_dir = self
            .working_dir
            .create()
            .map_err(|err| Error::WorkingDir(Box::new(err)))?;

        let path = working_dir.as_ref();

        // clone or open repository
        let repo = self.clone_or_update_repo(path)?;
        log::info!("Repository cloned or updated");

        // discover files between "then" and now
        let changes = self.find_changes(&repo)?;

        // discover and process files

        let mut path = Cow::Borrowed(path);
        if let Some(base) = &self.path {
            let new_path = path.join(base);

            log::debug!("  Base: {}", path.display());
            log::debug!("Target: {}", new_path.display());

            // ensure that self.path was a relative sub-directory of the repository
            let _ = new_path
                .strip_prefix(path)
                .map_err(|_| Error::Path(base.into()))?;

            path = new_path.into();
        }

        self.walk(&path, &changes)?;

        let head = repo.head()?;
        let commit = head.peel_to_commit()?.id();
        log::info!("Most recent commit: {commit}");

        // only drop when we are done, as this might delete the working directory

        drop(working_dir);

        // return result

        Ok(Continuation(Some(commit.to_string())))
    }

    fn clone_or_update_repo(&self, path: &Path) -> Result<Repository, Error> {
        match self.clone_repo(path) {
            Ok(repo) => Ok(repo),
            Err(err) if err.code() == ErrorCode::Exists && err.class() == ErrorClass::Invalid => {
                log::info!("Already exists, opening ...");
                let repo = info_span!("open repository").in_scope(|| Repository::open(path))?;

                let repo = info_span!("fetching updates").in_scope(move || {
                    self.progress
                        .message_sync(format!("Fetching updates: {}", self.source));
                    {
                        let mut remote = repo.find_remote("origin")?;
                        let mut fo = self.create_fetch_options();

                        match remote.fetch(&[] as &[&str], Some(&mut fo), None) {
                            Ok(()) => {}
                            Err(err)
                                if err.code() == ErrorCode::NotFound
                                    && err.class() == ErrorClass::Odb =>
                            {
                                // delete repo

                                remove_dir_all(path)?;

                                // clone repo

                                return Ok(self.clone_repo(path)?);
                            }
                            err => err?,
                        }
                        remote.disconnect()?;
                    }

                    log::info!("Fetched, resetting");

                    {
                        let head = repo.find_reference("FETCH_HEAD")?;
                        let head = head.peel_to_commit()?;

                        // reset to the most recent commit
                        repo.reset(head.as_object(), ResetType::Hard, None)?;
                    }

                    Ok::<_, Error>(repo)
                })?;

                Ok(repo)
            }
            Err(err) => {
                log::info!(
                    "Clone failed - code: {:?}, class: {:?}",
                    err.code(),
                    err.class()
                );
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self), err)]
    fn clone_repo(&self, path: &Path) -> Result<Repository, git2::Error> {
        self.progress
            .message_sync(format!("Cloning repository: {}", self.source));

        let mut builder = RepoBuilder::new();

        if let Some(branch) = &self.branch {
            builder.branch(branch);
        }

        let mut fo = self.create_fetch_options();
        if self.continuation.0.is_none() {
            fo.depth(self.depth);
        }

        builder.fetch_options(fo).clone(&self.source, path)
    }

    fn find_changes(&self, repo: &Repository) -> Result<Option<HashSet<PathBuf>>, Error> {
        let result = match &self.continuation.0 {
            Some(commit) => {
                log::info!("Continuing from: {commit}");

                info_span!("continue from", commit).in_scope(|| {
                    let start = match repo.find_commit(repo.revparse_single(commit)?.id()) {
                        Ok(start) => start,
                        Err(err)
                            if err.code() == ErrorCode::NotFound
                                && err.class() == ErrorClass::Odb =>
                        {
                            return Ok::<_, Error>(None);
                        }
                        err => err?,
                    };
                    let end = repo.head()?.peel_to_commit()?;

                    let start = start.tree()?;
                    let end = end.tree()?;

                    let diff = repo.diff_tree_to_tree(Some(&start), Some(&end), None)?;

                    let mut files = HashSet::with_capacity(diff.deltas().len());

                    for delta in diff.deltas() {
                        if let Some(path) = delta.new_file().path() {
                            let path = match &self.path {
                                // files are relative to the base dir
                                Some(base) => match path.strip_prefix(base) {
                                    Ok(path) => Some(path.to_path_buf()),
                                    Err(..) => None,
                                },
                                // files are relative to the repo
                                None => Some(path.to_path_buf()),
                            };

                            if let Some(path) = path {
                                log::debug!("Record {} as changed file", path.display());
                                files.insert(path);
                            }
                        }
                    }

                    Ok(Some(files))
                })?
            }
            _ => None,
        };

        match &result {
            Some(result) => {
                log::info!("Detected {} changed files", result.len());
            }
            None => {
                log::info!("Ingesting all files");
            }
        }

        Ok(result)
    }

    fn create_fetch_options(&self) -> FetchOptions<'_> {
        let mut cb = RemoteCallbacks::new();
        cb.transfer_progress(|progress| {
            let received = progress.received_objects();
            let total = progress.total_objects();
            let bytes = progress.received_bytes();

            log::trace!("Progress - objects: {received} of {total}, bytes: {bytes}");

            !self.handler.is_canceled()
        });
        cb.update_tips(|refname, a, b| {
            if a.is_zero() {
                log::debug!("[new]     {b:20} {refname}");
            } else {
                log::debug!("[updated] {a:10}..{b:10} {refname}");
            }
            !self.handler.is_canceled()
        });
        cb.sideband_progress(|_| !self.handler.is_canceled());

        let home = env::var("HOME").ok();
        if let Some(home) = home {
            for key in &["id_rsa", "id_ed25519"] {
                let key = Path::new(&home).join(".ssh").join(key);
                if key.exists() {
                    cb.credentials(move |_url, username_from_url, _allowed_types| {
                        Cred::ssh_key(username_from_url.unwrap_or(""), None, &key, None)
                    });
                    break;
                }
            }
        }

        let mut fo = FetchOptions::new();
        fo.remote_callbacks(cb);
        fo.depth(i32::MAX);
        fo
    }

    #[instrument(skip(self, changes), err)]
    fn walk(&self, base: &Path, changes: &Option<HashSet<PathBuf>>) -> Result<(), Error> {
        let mut collected = vec![];

        for entry in WalkDir::new(base)
            .into_iter()
            .filter_entry(|entry| !is_hidden(entry))
        {
            let entry = entry?;

            log::trace!("Checking: {entry:?}");

            if !entry.file_type().is_file() {
                continue;
            }

            // the path in the filesystem
            let path = entry.path();
            // the path, relative to the base (plus repo) dir
            let path = path.strip_prefix(base).unwrap_or(path);

            if let Some(changes) = changes
                && !changes.contains(path)
            {
                log::trace!("Skipping {}, as file did not change", path.display());
                continue;
            }

            let path = path.to_path_buf();
            collected.push((entry, path));
        }

        let mut progress = self.progress.start(collected.len());

        for (entry, path) in collected {
            self.handler
                .process(entry.path(), &path)
                .map_err(|err| match err {
                    HandlerError::Canceled => Error::Canceled,
                    HandlerError::Processing(err) => Error::Processing(anyhow!("{err}")),
                })?;

            progress.tick_sync();
        }

        progress.finish_sync();

        Ok(())
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Continuation(Option<String>);

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

use crate::runner::common::Error;
use crate::runner::progress::{Progress, ProgressInstance};

#[cfg(test)]
mod test {
    use super::{Continuation, GitWalker};
    use git2::{Repository, ResetType};
    use std::path::{Path, PathBuf};

    /// reset a git repository to the spec and return the commit as continuation
    pub(crate) fn git_reset(path: &Path, spec: &str) -> anyhow::Result<Continuation> {
        let repo = Repository::open(path)?;

        let r#ref = repo.revparse_single(spec)?;
        repo.reset(&r#ref, ResetType::Hard, None)?;

        let commit = r#ref.peel_to_commit()?.id().to_string();

        Ok(Continuation(Some(commit)))
    }

    #[test_log::test(tokio::test)]
    async fn test_walker() -> Result<(), anyhow::Error> {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from(format!(
            "{}target/test.data/test_walker.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));
        if path.exists() {
            std::fs::remove_dir_all(path.clone())?;
        }

        let cont = Continuation::default();

        let walker = GitWalker::new(SOURCE, ())
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path.clone())
            .depth(3);

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = GitWalker::new(SOURCE, ())
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");

        Ok(())
    }

    /// ensure that using `path`, we can't escape the repo directory
    #[test_log::test(tokio::test)]
    async fn test_walker_fail_escape() {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from(format!(
            "{}target/test.data/test_walker_fail_escape.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));

        let cont = Continuation::default();

        let walker = GitWalker::new(SOURCE, ())
            .path(Some("/etc"))
            .continuation(cont)
            .working_dir(path.clone());

        let r = walker.run().await;

        // must fail as we try to escape the repository root
        assert!(r.is_err());
    }
}
