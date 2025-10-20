use crate::service::{
    StorageBackend, StorageKey, StorageResult, StoreError, compression::Compression, temp::TempFile,
};
use anyhow::Context;
use bytes::Bytes;
use futures::Stream;
use std::{
    fmt::Debug,
    io::{ErrorKind, Result as IoResult},
    path::{Path, PathBuf},
};
use strum::IntoEnumIterator;
use tempfile::{TempDir, tempdir};
use tokio::{
    fs::{File, create_dir_all, remove_file, try_exists},
    io::{AsyncRead, AsyncWriteExt},
};
use tokio_util::io::ReaderStream;
use tracing::instrument;

/// A filesystem backed store
///
/// ## Layout
///
/// The layout of the filesystem is as follows:
///
/// ```text
/// <base>/
///   content/
///     <digest[0..2]>/
///       <digest[2..4]>/
///         <digest> # file
/// ```
///
/// The idea behind that is to limit the number of directory entries. For some filesystems,
/// the performance can degrade if directories get too big (have too many entries).
///
/// This layout limits the number of entries on the first two layers to 256, and limits the chance
/// of a file ending up in the same directory by 65536. Assuming an average distribution of hashes,
/// that would allow us to store 16777216 files, until we hit the cap of 256 entries in the lowest
/// lever directories. Should we need to increase that limit, we could easily add an additional
/// layer.
#[derive(Clone, Debug)]
pub struct FileSystemBackend {
    content: PathBuf,
    /// The compression algorithm to create new files with
    write_compression: Compression,
    /// The compression algorithm to detect files for
    read_compressions: Vec<Compression>,
}

const NUM_LEVELS: usize = 2;

impl FileSystemBackend {
    pub async fn new(base: impl Into<PathBuf>, compression: Compression) -> anyhow::Result<Self> {
        let base = base.into();
        let content = base.join("content");

        create_dir_all(&content)
            .await
            .or_else(|err| {
                if err.kind() == ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(err)
                }
            })
            .with_context(|| {
                format!(
                    "unable to create 'content' directory in the file system base: {}",
                    base.display()
                )
            })?;

        // For the read compressions, we put the write format first, as the assumption is, that it
        // is the one being used, and so we try it first. Afterward, all others.

        let mut read_compressions = vec![compression];
        read_compressions.extend(Compression::iter().filter(|c| c != &compression));

        Ok(Self {
            content,
            write_compression: compression,
            read_compressions,
        })
    }

    /// Create a new storage for testing
    pub async fn for_test() -> anyhow::Result<(Self, TempDir)> {
        let dir = tempdir()?;

        Self::new(dir.path(), Compression::None)
            .await
            .map(|result| (result, dir))
    }

    /// Create a new storage for testing
    pub async fn for_test_with(compression: Compression) -> anyhow::Result<(Self, TempDir)> {
        let dir = tempdir()?;

        Self::new(dir.path(), compression)
            .await
            .map(|result| (result, dir))
    }

    async fn locate(
        &self,
        StorageKey(hash): StorageKey,
    ) -> IoResult<Option<(PathBuf, Compression)>> {
        let mut target = level_dir(&self.content, &hash, NUM_LEVELS).join(&hash);
        for compression in &self.read_compressions {
            target.set_extension(compression.extension());
            if try_exists(&target).await? {
                return Ok(Some((target, *compression)));
            }
        }
        Ok(None)
    }
}

impl StorageBackend for FileSystemBackend {
    type Error = std::io::Error;

    #[instrument(skip(stream), err(Debug, level=tracing::Level::INFO))]
    async fn store<S>(&self, stream: S) -> Result<StorageResult, StoreError<Self::Error>>
    where
        S: AsyncRead + Unpin,
    {
        let mut file = TempFile::new(stream).await?;
        let mut source = file.reader().await?;

        let result = file.to_result();
        let key = result.key().to_string();

        // create the target path

        let target = level_dir(&self.content, &key, NUM_LEVELS);
        create_dir_all(&target).await?;
        let mut target = target.join(&key);
        target.set_extension(self.write_compression.extension());

        let mut target = File::create(target).await?;
        self.write_compression
            .write(&mut source, &mut target)
            .await?;

        // ensure we have all bytes on disk for the target file,
        // then close it

        target.flush().await?;
        drop(target);

        // the content is at the right place, close (destroy) the temp file

        drop(source);

        // done

        Ok(result)
    }

    async fn retrieve<'a>(
        &self,
        key: StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + 'a>, Self::Error> {
        match self.locate(key).await? {
            Some((path, compression)) => File::open(&path)
                .await
                .map(|f| Some(ReaderStream::new(compression.reader(f)))),
            None => Ok(None),
        }
    }

    async fn delete(&self, key: StorageKey) -> Result<(), Self::Error> {
        match self.locate(key).await? {
            Some((path, _)) => remove_file(path).await,
            None => Ok(()),
        }
    }
}

fn level_dir(base: impl AsRef<Path>, hash: &str, levels: usize) -> PathBuf {
    let prefixes = hash
        .chars()
        .take(levels * 2)
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect())
        .collect::<Vec<String>>();

    let mut path = base.as_ref().to_path_buf();

    for prefix in prefixes {
        path = path.join(prefix);
    }

    path
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::{
        dispatch::DispatchBackend,
        test::{test_read_not_found, test_store_read_and_delete},
    };
    use bytes::BytesMut;
    use futures::StreamExt;
    use rstest::rstest;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    use test_log::test;

    #[test]
    fn test_level_dir() {
        assert_eq!(level_dir("/", "1234567890", 2,), Path::new("/12/34"));
    }

    async fn backend(compression: Compression) -> (DispatchBackend, TempDir) {
        let dir = tempdir().unwrap();
        (
            FileSystemBackend::new(dir.path(), compression)
                .await
                .unwrap()
                .into(),
            dir,
        )
    }

    #[test(tokio::test)]
    async fn store() {
        const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

        let (backend, dir) = backend(Compression::None).await;

        let digest = backend
            .store(&b"Hello World"[..])
            .await
            .expect("store must succeed");

        assert_eq!(digest.key().to_string(), DIGEST);

        let target = dir
            .path()
            .join("content")
            .join(&DIGEST[0..2])
            .join(&DIGEST[2..4])
            .join(DIGEST);

        assert!(target.exists());
        let data = std::fs::read(target).unwrap();
        assert_eq!(hex::encode(Sha256::digest(data)), DIGEST);
    }

    #[test(tokio::test)]
    #[rstest]
    #[case(Compression::None)]
    #[case(Compression::Zstd)]
    async fn store_read_and_delete(#[case] compression: Compression) {
        let (backend, _dir) = backend(compression).await;

        test_store_read_and_delete(backend).await
    }

    /// This test should ensure that we can also read compression algorithm other than the
    /// configured write format.
    #[test(tokio::test)]
    async fn test_store_and_read_dff() {
        const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

        let dir = tempdir().unwrap();
        let backend = FileSystemBackend::new(dir.path(), Compression::Zstd)
            .await
            .unwrap();

        let digest = backend
            .store(&b"Hello World"[..])
            .await
            .expect("store must succeed");

        assert_eq!(digest.key().to_string(), DIGEST);

        let backend = FileSystemBackend::new(dir.path(), Compression::None)
            .await
            .unwrap();

        let mut stream = backend
            .retrieve(digest.key())
            .await
            .expect("retrieve must succeed")
            .expect("must be found");

        let mut content = BytesMut::new();
        while let Some(data) = stream.next().await {
            content.extend(&data.expect("read must succeed"));
        }

        assert_eq!(content.as_ref(), b"Hello World");
    }

    /// Ensure retrieving the information that the file does not exist works.
    #[test(tokio::test)]
    async fn read_not_found() {
        let (backend, _dir) = backend(Compression::None).await;

        test_read_not_found(backend).await;
    }
}
