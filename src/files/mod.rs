//! Filesystem bridge for local-first deployments.
//!
//! google-mcp-rs is designed to run on the same machine as its MCP client
//! (see the README's "Deployment posture"). When the operator sets
//! `FILE_ROOT` and bind-mounts that directory into the container, the file
//! tools can **read attachments from** and **write downloads to** a jailed
//! host directory directly — so file bytes never have to travel through the
//! model's context as base64. Base64 stays available as a fallback for
//! genuinely-remote clients, but paths are the fast, reliable path.
//!
//! Everything here enforces a single invariant: a resolved path is always
//! inside the canonicalized `FILE_ROOT`. Absolute paths must live under it;
//! relative paths are joined onto it. Symlink escapes are rejected by
//! canonicalizing before the containment check.

use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

/// Above this many raw bytes, returning a download inline as base64 would
/// bloat the model's context. When a FILE_ROOT jail is available (so the
/// caller has a `dest_path` alternative), downloads larger than this are
/// refused inline and the caller is nudged toward writing to disk.
pub const INLINE_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error(
        "filesystem file exchange is not enabled on this server (FILE_ROOT is unset). \
         Pass file bytes via base64 instead, or ask the operator to set FILE_ROOT + bind-mount it."
    )]
    Disabled,
    #[error(
        "path `{path}` resolves outside the file-exchange root `{root}`. \
         Only paths inside the exchange directory are allowed."
    )]
    Escape { path: String, root: String },
    #[error("no such file: {0}")]
    NotFound(String),
    #[error("not a regular file: {0}")]
    NotAFile(String),
    #[error("io error on `{path}`: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// A canonicalized directory that scopes every filesystem read/write the
/// file tools are allowed to perform. Cheap to clone.
#[derive(Clone, Debug)]
pub struct FileJail {
    root: PathBuf,
}

impl FileJail {
    /// Build a jail from the operator-supplied `FILE_ROOT`. Returns:
    /// - `Ok(None)` when `root` is `None`/empty (feature disabled),
    /// - `Ok(Some(jail))` when the directory exists (or was created) and canonicalizes,
    /// - `Err(_)` when a configured root can't be created/resolved — a hard
    ///   startup error so the operator notices a broken mount immediately.
    pub fn from_env(root: Option<&str>) -> Result<Option<Self>, FileError> {
        let Some(raw) = root.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let path = PathBuf::from(raw);
        // Create the root if it isn't there yet so a fresh deployment works
        // without a manual mkdir. If the bind mount is missing this creates a
        // container-local dir instead — acceptable; the operator's mount, when
        // present, shadows it.
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(|e| FileError::Io {
                path: raw.to_string(),
                source: e,
            })?;
        }
        let canon = std::fs::canonicalize(&path).map_err(|e| FileError::Io {
            path: raw.to_string(),
            source: e,
        })?;
        Ok(Some(Self { root: canon }))
    }

    /// The canonical root, for surfacing in errors / diagnostics.
    #[allow(dead_code)] // used in tests + kept as a diagnostic accessor
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Join a caller-supplied path onto the root. Absolute inputs are taken
    /// as-is (they must still land inside the root); relative inputs are
    /// resolved against the root.
    fn join(&self, input: &str) -> PathBuf {
        let p = Path::new(input);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.root.join(p)
        }
    }

    /// Resolve a path to READ from. The file must exist, be a regular file,
    /// and canonicalize to somewhere inside the root.
    pub fn resolve_read(&self, input: &str) -> Result<PathBuf, FileError> {
        let joined = self.join(input);
        let canon = std::fs::canonicalize(&joined).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FileError::NotFound(input.to_string())
            } else {
                FileError::Io {
                    path: input.to_string(),
                    source: e,
                }
            }
        })?;
        if !canon.starts_with(&self.root) {
            return Err(FileError::Escape {
                path: input.to_string(),
                root: self.root.display().to_string(),
            });
        }
        if !canon.is_file() {
            return Err(FileError::NotAFile(input.to_string()));
        }
        Ok(canon)
    }

    /// Resolve a path to WRITE to. The file need not exist, but its parent
    /// (after creating any intermediate dirs inside the root) must resolve
    /// inside the root. Returns the absolute path to write.
    pub fn resolve_write(&self, input: &str) -> Result<PathBuf, FileError> {
        let joined = self.join(input);
        // Lexical containment first — catches `..` traversal before we touch
        // the filesystem, so we never create dirs outside the root.
        let lexical = lexically_normalize(&joined);
        if !lexical.starts_with(&self.root) {
            return Err(FileError::Escape {
                path: input.to_string(),
                root: self.root.display().to_string(),
            });
        }
        let file_name = lexical.file_name().ok_or_else(|| FileError::Io {
            path: input.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination path has no file name",
            ),
        })?;
        let parent = lexical.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(parent).map_err(|e| FileError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
        // Canonicalize the now-existing parent to defeat symlink escapes.
        let canon_parent = std::fs::canonicalize(parent).map_err(|e| FileError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
        if !canon_parent.starts_with(&self.root) {
            return Err(FileError::Escape {
                path: input.to_string(),
                root: self.root.display().to_string(),
            });
        }
        Ok(canon_parent.join(file_name))
    }

    /// Read the full contents of a jailed path.
    pub fn read(&self, input: &str) -> Result<Vec<u8>, FileError> {
        let path = self.resolve_read(input)?;
        std::fs::read(&path).map_err(|e| FileError::Io {
            path: input.to_string(),
            source: e,
        })
    }

    /// Write bytes to a jailed path, returning the absolute path written.
    pub fn write(&self, input: &str, bytes: &[u8]) -> Result<PathBuf, FileError> {
        let path = self.resolve_write(input)?;
        std::fs::write(&path, bytes).map_err(|e| FileError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(path)
    }

    /// List every regular file under the root (recursively), skipping the
    /// reserved `keep/` subtree and any symlinks. Used by the `files_info` /
    /// `files_cleanup` tools.
    ///
    /// Tolerant by design: individual files or subdirectories the process
    /// can't stat/enter (common when the root is a broad directory like the
    /// user's Downloads, which may hold app-private subdirs) are silently
    /// skipped rather than failing the whole scan. Only an unreadable *root*
    /// is a hard error.
    pub fn scan(&self) -> Result<Vec<DirEntryInfo>, FileError> {
        let rd = std::fs::read_dir(&self.root).map_err(|e| FileError::Io {
            path: self.root.display().to_string(),
            source: e,
        })?;
        let mut out = Vec::new();
        scan_entries(&self.root, rd, &mut out);
        Ok(out)
    }

    /// Delete a single regular file, but only if it resolves inside the root
    /// and isn't in the reserved `keep/` subtree. Returns the bytes freed.
    pub fn remove_file(&self, path: &Path) -> Result<u64, FileError> {
        let canon = std::fs::canonicalize(path).map_err(|e| FileError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if !canon.starts_with(&self.root) {
            return Err(FileError::Escape {
                path: path.display().to_string(),
                root: self.root.display().to_string(),
            });
        }
        if is_in_keep(&self.root, &canon) {
            return Err(FileError::Io {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing to delete inside the reserved keep/ subdirectory",
                ),
            });
        }
        let size = std::fs::metadata(&canon).map(|m| m.len()).unwrap_or(0);
        std::fs::remove_file(&canon).map_err(|e| FileError::Io {
            path: canon.display().to_string(),
            source: e,
        })?;
        Ok(size)
    }
}

/// Metadata for one file found by [`FileJail::scan`].
#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
}

/// True if `path` lies within a top-level `keep/` directory under `root`.
fn is_in_keep(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root)
        .ok()
        .and_then(|rel| rel.components().next())
        .map(|c| c.as_os_str() == "keep")
        .unwrap_or(false)
}

fn scan_entries(root: &Path, rd: std::fs::ReadDir, out: &mut Vec<DirEntryInfo>) {
    for entry in rd.flatten() {
        let path = entry.path();
        // Never follow symlinks (defends against escapes) and skip the
        // reserved keep/ subtree entirely. Any entry we can't stat is skipped.
        let Ok(meta) = entry.metadata() else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if is_in_keep(root, &path) {
            continue;
        }
        if meta.is_dir() {
            // Skip (don't abort) subdirectories we can't enter.
            if let Ok(sub) = std::fs::read_dir(&path) {
                scan_entries(root, sub, out);
            }
        } else if meta.is_file() {
            out.push(DirEntryInfo {
                path,
                size: meta.len(),
                modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
    }
}

/// Select which scanned entries a cleanup would remove. Pure (takes `now`
/// explicitly) so it's deterministic to test. An entry is selected when it
/// passes BOTH filters that are present: age older than `older_than_secs`,
/// and name containing `name_contains` (case-insensitive). With neither
/// filter, every entry is selected.
pub fn plan_delete<'a>(
    entries: &'a [DirEntryInfo],
    now: SystemTime,
    older_than_secs: Option<u64>,
    name_contains: Option<&str>,
) -> Vec<&'a DirEntryInfo> {
    let needle = name_contains.map(|s| s.to_ascii_lowercase());
    entries
        .iter()
        .filter(|e| {
            if let Some(min_age) = older_than_secs {
                let age = now
                    .duration_since(e.modified)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if age < min_age {
                    return false;
                }
            }
            if let Some(n) = &needle {
                let name = e
                    .path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !name.contains(n) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Lexically normalize a path (resolve `.` and `..` textually, without
/// touching the filesystem). Used to reject traversal before we create dirs.
fn lexically_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Best-effort MIME type from a filename extension. Deliberately dependency-
/// free and covers the file types that actually flow through email/Drive.
/// Falls back to `application/octet-stream`.
pub fn guess_mime(filename: &str) -> &'static str {
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "heic" => "image/heic",
        "txt" | "text" | "log" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "ics" => "text/calendar",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_root() -> PathBuf {
        // Unique dir under the system temp; created for the test.
        let base = std::env::temp_dir();
        let mut n = base.clone();
        // Use process id + a counter to avoid Date/rand (unavailable in some
        // harnesses) while staying unique across parallel tests.
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        n.push(format!("gmcp-jail-test-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&n).unwrap();
        n
    }

    fn jail_at(root: &Path) -> FileJail {
        FileJail::from_env(Some(root.to_str().unwrap()))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn disabled_when_unset() {
        assert!(FileJail::from_env(None).unwrap().is_none());
        assert!(FileJail::from_env(Some("")).unwrap().is_none());
        assert!(FileJail::from_env(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn creates_root_if_missing() {
        let mut root = tmp_root();
        root.push("nested/exchange");
        let jail = jail_at(&root);
        assert!(jail.root().exists());
    }

    #[test]
    fn read_within_root_ok() {
        let root = tmp_root();
        let mut f = std::fs::File::create(root.join("hello.txt")).unwrap();
        f.write_all(b"hi there").unwrap();
        let jail = jail_at(&root);
        assert_eq!(jail.read("hello.txt").unwrap(), b"hi there");
        // Absolute path inside the root also works.
        let abs = root.join("hello.txt");
        assert_eq!(jail.read(abs.to_str().unwrap()).unwrap(), b"hi there");
    }

    #[test]
    fn read_missing_is_not_found() {
        let root = tmp_root();
        let jail = jail_at(&root);
        assert!(matches!(
            jail.read("nope.txt").unwrap_err(),
            FileError::NotFound(_)
        ));
    }

    #[test]
    fn read_directory_is_not_a_file() {
        let root = tmp_root();
        std::fs::create_dir(root.join("subdir")).unwrap();
        let jail = jail_at(&root);
        assert!(matches!(
            jail.read("subdir").unwrap_err(),
            FileError::NotAFile(_)
        ));
    }

    #[test]
    fn read_traversal_escape_rejected() {
        let root = tmp_root();
        // A secret sibling of the root.
        let secret = root.parent().unwrap().join(format!(
            "secret-{}-{}.txt",
            std::process::id(),
            root.file_name().unwrap().to_str().unwrap()
        ));
        std::fs::write(&secret, b"top secret").unwrap();
        let jail = jail_at(&root);
        let rel = format!("../{}", secret.file_name().unwrap().to_str().unwrap());
        assert!(matches!(
            jail.read(&rel).unwrap_err(),
            FileError::Escape { .. }
        ));
        // Absolute outside path is rejected too.
        assert!(matches!(
            jail.read(secret.to_str().unwrap()).unwrap_err(),
            FileError::Escape { .. }
        ));
        let _ = std::fs::remove_file(&secret);
    }

    #[test]
    fn write_within_root_creates_dirs() {
        let root = tmp_root();
        let jail = jail_at(&root);
        let written = jail.write("out/deep/report.pdf", b"%PDF-1.7").unwrap();
        assert!(written.starts_with(jail.root()));
        assert_eq!(std::fs::read(&written).unwrap(), b"%PDF-1.7");
    }

    #[test]
    fn write_traversal_escape_rejected() {
        let root = tmp_root();
        let jail = jail_at(&root);
        let err = jail.write("../escape.txt", b"x").unwrap_err();
        assert!(matches!(err, FileError::Escape { .. }));
        // The file must not have been created outside the root.
        assert!(!root.parent().unwrap().join("escape.txt").exists());
    }

    #[test]
    fn scan_finds_files_and_skips_keep_and_dirs() {
        let root = tmp_root();
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/b.txt"), b"bb").unwrap();
        std::fs::create_dir_all(root.join("keep")).unwrap();
        std::fs::write(root.join("keep/protected.txt"), b"keep me").unwrap();
        let jail = jail_at(&root);
        let mut found: Vec<String> = jail
            .scan()
            .unwrap()
            .into_iter()
            .map(|e| e.path.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        found.sort();
        assert_eq!(found, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn plan_delete_filters_by_age_and_name() {
        let now = SystemTime::now();
        let old = now - std::time::Duration::from_secs(10 * 3600);
        let fresh = now - std::time::Duration::from_secs(60);
        let entries = vec![
            DirEntryInfo {
                path: PathBuf::from("/x/old-report.pdf"),
                size: 100,
                modified: old,
            },
            DirEntryInfo {
                path: PathBuf::from("/x/fresh-report.pdf"),
                size: 200,
                modified: fresh,
            },
            DirEntryInfo {
                path: PathBuf::from("/x/old-note.txt"),
                size: 50,
                modified: old,
            },
        ];
        // Age filter: > 5h selects the two old ones.
        let by_age = plan_delete(&entries, now, Some(5 * 3600), None);
        assert_eq!(by_age.len(), 2);
        // Name filter combines with age (AND): old + contains "report".
        let both = plan_delete(&entries, now, Some(5 * 3600), Some("REPORT"));
        assert_eq!(both.len(), 1);
        assert!(both[0].path.ends_with("old-report.pdf"));
        // No filters: everything.
        assert_eq!(plan_delete(&entries, now, None, None).len(), 3);
    }

    #[test]
    fn remove_file_refuses_keep_subtree() {
        let root = tmp_root();
        std::fs::create_dir_all(root.join("keep")).unwrap();
        let protected = root.join("keep/x.txt");
        std::fs::write(&protected, b"x").unwrap();
        let jail = jail_at(&root);
        assert!(jail.remove_file(&protected).is_err());
        assert!(protected.exists(), "keep/ file must survive");
        // A normal file deletes fine.
        let normal = root.join("y.txt");
        std::fs::write(&normal, b"yy").unwrap();
        assert_eq!(jail.remove_file(&normal).unwrap(), 2);
        assert!(!normal.exists());
    }

    #[test]
    fn guess_mime_common_types() {
        assert_eq!(guess_mime("a.pdf"), "application/pdf");
        assert_eq!(guess_mime("photo.JPG"), "image/jpeg");
        assert_eq!(guess_mime("data.csv"), "text/csv");
        assert_eq!(
            guess_mime("sheet.xlsx"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        );
        assert_eq!(guess_mime("mystery"), "application/octet-stream");
        assert_eq!(guess_mime("archive.tar.gz"), "application/gzip");
    }
}
