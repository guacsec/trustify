use crate::resource::TestResource;
use anyhow::{Context, anyhow, bail};
use async_compression::tokio::bufread::XzDecoder;
use futures::future::BoxFuture;
use postgresql_embedded::{PostgreSQL, Settings};
use std::{
    ffi::OsStr,
    fmt::Debug,
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
use tokio::fs;
use trustify_common::{config, db::Database};
use trustify_db::embedded::default_settings;
use trustify_module_storage::service::fs::FileSystemBackend;

pub fn is_supported() -> bool {
    Command::new().is_ok()
}

#[derive(Clone, Debug)]
struct Command {
    pub btrfs: PathBuf,
    pub store: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl Command {
    pub fn new() -> anyhow::Result<Self> {
        bail!("btrfs is only supported on Linux");
    }
}

#[cfg(target_os = "linux")]
impl Command {
    /// Find the mount info entry for the given path (longest mount point prefix match).
    fn find_mount_entry(path: impl AsRef<Path>) -> io::Result<Option<procfs::process::MountInfo>> {
        let path = path.as_ref().canonicalize()?;
        let me = procfs::process::Process::myself().map_err(io::Error::other)?;
        let mountinfo = me.mountinfo().map_err(io::Error::other)?;

        Ok(mountinfo
            .into_iter()
            .filter(|m| path.starts_with(&m.mount_point))
            .max_by_key(|m| m.mount_point.as_os_str().len()))
    }

    pub fn new() -> anyhow::Result<Self> {
        if std::env::var_os("TRUST_TEST_BTRFS_DISABLE").is_some() {
            bail!("btrfs support disabled via TRUST_TEST_BTRFS_DISABLE");
        }

        let btrfs = which::which("btrfs").context(
            r#"unable to locate btrfs:

You can install `btrfs`:
  * On Fedora using: sudo dnf install btrfs-progs

"#,
        )?;

        let store = match std::env::var_os("TRUST_TEST_BTRFS_STORE") {
            Some(store) => Some(PathBuf::from(store)),
            None => std::env::current_dir().ok(),
        }
        .ok_or_else(|| anyhow!("unable to locate btrfs store"))?;

        let mount_entry = Self::find_mount_entry(store.as_path())?.ok_or_else(|| {
            anyhow!(
                "unable to find mount entry for btrfs store ({})",
                store.display()
            )
        })?;

        if mount_entry.fs_type != "btrfs" {
            bail!(
                r#"btrfs store ({}) is not on a btrfs volume.

You can set `TRUST_TEST_BTRFS_STORE` to a directory on a BTRFS volume mounted with: defaults,user,exec,user_subvol_rm_allowed
"#,
                store.display()
            );
        }

        if !mount_entry
            .super_options
            .contains_key("user_subvol_rm_allowed")
        {
            bail!(
                r#"btrfs store ({}) is missing the `user_subvol_rm_allowed` mount option.

Remount the volume with: defaults,user,exec,user_subvol_rm_allowed
Or update /etc/fstab and remount.
"#,
                store.display()
            );
        }

        Ok(Self { btrfs, store })
    }

    async fn execute(
        &self,
        args: impl IntoIterator<Item = impl AsRef<OsStr> + Debug>,
    ) -> anyhow::Result<()> {
        let args = args.into_iter().collect::<Vec<_>>();
        log::info!("{} {args:?}", self.btrfs.display());

        let mut command = tokio::process::Command::new(&self.btrfs);

        command.args(args);

        let status = command.status().await?;

        if !status.success() {
            bail!("btrfs exited with status {}", status);
        }

        Ok(())
    }
}

pub struct SnapshotProvider {
    pub id: String,
    /// snapshot archive
    pub file: Option<PathBuf>,
}

impl SnapshotProvider {
    async fn provide(&self, btrfs: &Command) -> anyhow::Result<Option<BtrfsSnapshot>> {
        let template = btrfs.store.join("templates").join(&self.id);
        if template.is_dir() {
            return Ok(Some(BtrfsSnapshot {
                btrfs: btrfs.clone(),
                id: self.id.to_string(),
            }));
        }

        // detect existing snapshot file

        if self.load_snapshot(btrfs).await? {
            log::info!("Imported new snapshot");
            return Ok(Some(BtrfsSnapshot {
                btrfs: btrfs.clone(),
                id: self.id.to_string(),
            }));
        }

        Ok(None)
    }

    /// if the snapshot file exists, do load it
    async fn load_snapshot(&self, btrfs: &Command) -> anyhow::Result<bool> {
        // check if snapshot archive is present

        let Some(snapshot_file) = &self.file else {
            // file wasn't there
            log::info!("Snapshot file wasn't available");
            return Ok(false);
        };

        log::info!("Extracting snapshot from: {}", snapshot_file.display());

        let templates = btrfs.store.join("templates");
        fs::create_dir_all(&templates).await?;

        let target = templates.join(&self.id);

        btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("create"),
                target.as_os_str(),
            ])
            .await?;

        let file = fs::File::open(&snapshot_file).await.with_context(|| {
            format!("failed to open snapshot file: {}", snapshot_file.display())
        })?;

        let decoder = XzDecoder::new(tokio::io::BufReader::new(file));
        let archive = async_tar::Archive::new(decoder);
        archive
            .unpack(&target)
            .await
            .context("failed to extract snapshot into subvolume")?;

        log::info!("Snapshot extracted into templates/{}", self.id);

        Ok(true)
    }
}

/// A running content instance
#[derive(Debug)]
pub enum Running {
    /// Plain simple temp dir
    Temporary(TempDir),
    /// Using an existing, ready to use, snapshot
    Existing(BtrfsSnapshot),
    /// A preparation step to create a snapshot
    Collecting(Collect),
}

impl Running {
    pub async fn new(provider: SnapshotProvider) -> anyhow::Result<Self> {
        let btrfs = match Command::new() {
            Ok(btrfs) => btrfs,
            Err(err) => {
                log::warn!("failed to detect btrfs support: {}", err);
                return Ok(Running::Temporary(TempDir::new()?));
            }
        };

        // detect existing template

        if let Some(snapshot) = provider.provide(&btrfs).await? {
            return Ok(Running::Existing(snapshot));
        }

        // return new collecting

        Ok(Running::Collecting(Collect::new(btrfs, provider.id).await?))
    }
}

/// A mounted snapshot, ready to use
#[derive(Debug)]
pub struct BtrfsSnapshot {
    btrfs: Command,
    id: String,
}

impl BtrfsSnapshot {
    pub async fn start(&self) -> anyhow::Result<BtrfsStarted> {
        // mount

        let snapshot = self.btrfs.store.join("templates").join(&self.id);

        let running = self.btrfs.store.join("running");
        fs::create_dir_all(&running).await?;
        let running = running.join(uuid::Uuid::new_v4().to_string());

        // create volume (running) from snapshot

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                snapshot.as_os_str(),
                running.as_os_str(),
            ])
            .await?;

        // create instances

        let storage = FileSystemBackend::for_test_in(running.join("storage")).await?;

        let db_base = running.join("db");
        fs::set_permissions(&db_base, std::fs::Permissions::from_mode(0o700)).await?;

        let settings = Settings {
            // data_dir: db_base.join("data"),
            data_dir: db_base,
            temporary: false,
            timeout: Some(Duration::from_mins(2)),
            username: "trustify".to_string(),
            ..default_settings()?
        };
        let mut psql = PostgreSQL::new(settings);
        psql.setup().await?;
        psql.start().await.inspect_err(|_| {
            let log = std::fs::read_to_string(psql.settings().data_dir.join("start.log"))
                .unwrap_or_default();
            log::info!("{}", log);
        })?;

        let db = config::Database {
            url: None,
            username: psql.settings().username.clone(),
            password: psql.settings().password.clone().into(),
            host: psql.settings().host.clone(),
            port: psql.settings().port,
            name: "trustify".into(),
            ..config::Database::from_env()?
        };

        // done

        Ok(BtrfsStarted {
            btrfs: self.btrfs.clone(),
            storage,
            db: Database::new(&db).await?,
            psql,
            path: running,
        })
    }
}

pub struct BtrfsStarted {
    storage: FileSystemBackend,
    psql: PostgreSQL,
    db: Database,
    path: PathBuf,
    btrfs: Command,
}

impl BtrfsStarted {
    pub fn storage(&self) -> &FileSystemBackend {
        &self.storage
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn settings(&self) -> &Settings {
        self.psql.settings()
    }

    pub async fn stop(self) -> anyhow::Result<()> {
        // stop the database

        let _ = self.psql.stop().await;

        // delete the subvolume

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("delete"),
                self.path.as_os_str(),
            ])
            .await?;

        // done

        Ok(())
    }
}

impl TestResource for BtrfsStarted {
    fn drop(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let _ = self.stop().await;
        })
    }
}

#[derive(Debug)]
pub struct Collect {
    // directory to prepare in
    path: PathBuf,
    btrfs: Command,
    id: String,
}

impl Collect {
    async fn new(btrfs: Command, id: String) -> anyhow::Result<Self> {
        let path = btrfs.store.join("prepare");
        fs::create_dir_all(&path).await?;
        let path = path.join(&id);

        if path.exists() {
            log::info!(
                "Deleting existing preparation directory: {}",
                path.display()
            );

            btrfs
                .execute([
                    OsStr::new("subvolume"),
                    OsStr::new("delete"),
                    path.as_os_str(),
                ])
                .await?;
        }

        btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("create"),
                path.as_os_str(),
            ])
            .await?;

        Ok(Self { path, btrfs, id })
    }

    pub async fn create(self, psql: PostgreSQL) -> anyhow::Result<BtrfsSnapshot> {
        log::info!("Collecting snapshot");

        // stop the instance to allow creating a consistent snapshot

        psql.stop().await?;

        // take the snapshot

        let target = self.btrfs.store.join("templates");
        fs::create_dir_all(&target).await?;
        let target = target.join(&self.id);

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                self.path.as_os_str(),
                target.as_os_str(),
            ])
            .await?;

        // now delete the prepared volume

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("delete"),
                self.path.as_os_str(),
            ])
            .await?;

        // return the result

        Ok(BtrfsSnapshot {
            btrfs: self.btrfs,
            id: self.id,
        })
    }
}

impl AsRef<Path> for Collect {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
