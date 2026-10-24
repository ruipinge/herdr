//! Stage files that remote clients upload with the `endpoint.upload.*` controls.
//!
//! Each client's reader thread owns one [`UploadReceiver`], so disk writes never run on
//! the server's main loop. Acks are sent only after a chunk is written, which gives the
//! client real backpressure. Completed batches are handed to the main loop to paste.
//! Staged files outlive the connection; they are swept by age, not on detach, because
//! an agent may read a dropped document long after the client went away.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use tracing::{info, warn};

use crate::config::ServerUploadPolicy;
use crate::protocol::endpoint::{
    upload_control_message, EndpointUploadAck, EndpointUploadBegin, EndpointUploadChunk,
    EndpointUploadId, EndpointUploadResult, UPLOAD_ACK_KIND, UPLOAD_BEGIN_KIND, UPLOAD_CANCEL_KIND,
    UPLOAD_CAPABILITY, UPLOAD_CHUNK_BYTES, UPLOAD_CHUNK_KIND, UPLOAD_END_KIND,
    UPLOAD_FILES_CAPABILITY, UPLOAD_MAX_FILES, UPLOAD_RESULT_KIND,
};
use crate::protocol::{ClientClipboardImageTarget, ServerMessage};

/// Concurrent unfinished batches one client may hold open.
const MAX_OPEN_BATCHES: usize = 4;
const MAX_STAGED_NAME_BYTES: usize = 128;
const PARTIAL_SUFFIX: &str = ".partial";
/// Batch directories are `herdr-upload-<nanos>-<client>-<id>`. Only names with this
/// prefix are ever swept, so a user-chosen `upload_dir` such as `~/Downloads` is safe.
const BATCH_DIR_PREFIX: &str = "herdr-upload-";
/// Per-drop cap when the owner has not enabled file uploads, close to the 16 MiB
/// single-frame image bridge this replaces.
const IMAGE_ONLY_MAX_BATCH_BYTES: u64 = 64 * 1024 * 1024;
/// Staged data kept across all batches, as a multiple of `server.upload_max_bytes`.
const STAGED_TOTAL_FACTOR: u64 = 4;

/// Capabilities to advertise in the endpoint welcome for the current server config.
pub(crate) fn advertised_capabilities(policy: &ServerUploadPolicy) -> Vec<&'static str> {
    // Windows staging is untested, so only Unix servers accept uploads for now.
    if !cfg!(unix) {
        return Vec::new();
    }
    let mut capabilities = vec![UPLOAD_CAPABILITY];
    if policy.accept_files {
        capabilities.push(UPLOAD_FILES_CAPABILITY);
    }
    capabilities
}

pub(crate) fn is_upload_kind(kind: &str) -> bool {
    // Matches `advertised_capabilities`: Windows servers ignore uploads entirely.
    cfg!(unix)
        && matches!(
            kind,
            UPLOAD_BEGIN_KIND | UPLOAD_CHUNK_KIND | UPLOAD_END_KIND | UPLOAD_CANCEL_KIND
        )
}

/// A batch whose files are all staged and ready to paste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedUpload {
    pub(crate) id: u64,
    pub(crate) target: ClientClipboardImageTarget,
    pub(crate) paths: Vec<PathBuf>,
}

impl StagedUpload {
    /// Text pasted into the target: paths separated by spaces. A single file pastes
    /// its bare path, exactly like the clipboard image bridge, so agents that attach a
    /// pasted image path keep recognizing it. Paths outside the safe character set are
    /// single-quoted for shells and agent prompts.
    pub(crate) fn paste_text(&self) -> String {
        self.paths
            .iter()
            .map(|path| quote_path(&path.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub(crate) fn result(
        &self,
        pasted: bool,
        not_pasted_reason: Option<&str>,
    ) -> EndpointUploadResult {
        EndpointUploadResult {
            id: self.id,
            ok: true,
            paths: self
                .paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            pasted,
            code: None,
            message: not_pasted_reason.map(str::to_owned),
        }
    }
}

pub(crate) fn result_message(result: &EndpointUploadResult) -> Option<ServerMessage> {
    upload_control_message(UPLOAD_RESULT_KIND, result).ok()
}

#[derive(Debug)]
pub(crate) enum UploadControlOutcome {
    Reply(ServerMessage),
    Staged(StagedUpload),
    Ignore,
}

struct StagedFile {
    final_path: PathBuf,
    partial_path: PathBuf,
    size: u64,
    written: u64,
}

struct Batch {
    target: ClientClipboardImageTarget,
    dir: PathBuf,
    files: Vec<StagedFile>,
    current: usize,
    handle: Option<fs::File>,
    received: u64,
}

type PolicyLoader = Box<dyn Fn() -> ServerUploadPolicy + Send>;

pub(crate) struct UploadReceiver {
    client_id: u64,
    load_policy: PolicyLoader,
    batches: HashMap<u64, Batch>,
}

impl UploadReceiver {
    /// Reads the server config at the start of each batch, so `server.accept_uploads`
    /// and limits apply without a restart.
    pub(crate) fn new(client_id: u64) -> Self {
        Self::with_policy_loader(
            client_id,
            Box::new(|| crate::config::Config::load().config.server_upload_policy()),
        )
    }

    pub(crate) fn with_policy_loader(client_id: u64, load_policy: PolicyLoader) -> Self {
        Self {
            client_id,
            load_policy,
            batches: HashMap::new(),
        }
    }

    pub(crate) fn handle(&mut self, kind: &str, data: &str) -> UploadControlOutcome {
        match kind {
            UPLOAD_BEGIN_KIND => match serde_json::from_str::<EndpointUploadBegin>(data) {
                Ok(begin) => self.begin(begin),
                Err(err) => self.malformed(data, "begin", &err),
            },
            UPLOAD_CHUNK_KIND => match serde_json::from_str::<EndpointUploadChunk>(data) {
                Ok(chunk) => self.chunk(chunk),
                Err(err) => self.malformed(data, "chunk", &err),
            },
            UPLOAD_END_KIND => match serde_json::from_str::<EndpointUploadId>(data) {
                Ok(end) => self.end(end.id),
                Err(_) => UploadControlOutcome::Ignore,
            },
            UPLOAD_CANCEL_KIND => {
                if let Ok(cancel) = serde_json::from_str::<EndpointUploadId>(data) {
                    if let Some(batch) = self.batches.remove(&cancel.id) {
                        discard(batch);
                    }
                }
                UploadControlOutcome::Ignore
            }
            _ => UploadControlOutcome::Ignore,
        }
    }

    /// Fail the batch named by a control this server cannot decode, so the client
    /// learns immediately instead of waiting for its stall timeout.
    fn malformed(
        &mut self,
        data: &str,
        what: &str,
        err: &serde_json::Error,
    ) -> UploadControlOutcome {
        warn!(client_id = self.client_id, err = %err, "malformed upload {what}");
        let Some(id) = serde_json::from_str::<serde_json::Value>(data)
            .ok()
            .and_then(|value| value.get("id")?.as_u64())
        else {
            return UploadControlOutcome::Ignore;
        };
        if let Some(batch) = self.batches.remove(&id) {
            discard(batch);
        }
        failure(
            id,
            "invalid",
            format!("this server cannot read the upload {what}"),
        )
    }

    fn begin(&mut self, begin: EndpointUploadBegin) -> UploadControlOutcome {
        let id = begin.id;
        if self.batches.contains_key(&id) {
            return failure(id, "duplicate", "upload id is already in use");
        }
        if self.batches.len() >= MAX_OPEN_BATCHES {
            return failure(id, "busy", "too many uploads in progress");
        }
        if begin.files.is_empty() || begin.files.len() > UPLOAD_MAX_FILES {
            return failure(
                id,
                "invalid",
                format!("an upload must contain 1 to {UPLOAD_MAX_FILES} files"),
            );
        }
        let Some(target) = begin.target.terminal_target() else {
            return failure(
                id,
                "invalid",
                "this server does not support that upload target",
            );
        };
        let policy = (self.load_policy)();
        let mut used = Vec::new();
        let names = begin
            .files
            .iter()
            .map(|file| unique_name(sanitize_file_name(&file.name), &mut used))
            .collect::<Vec<_>>();
        if !policy.accept_files
            && !names
                .iter()
                .all(|name| crate::config::is_image_file_name(name))
        {
            return failure(
                id,
                "files_disabled",
                "This server only accepts image uploads. Set server.accept_uploads = true in its config.",
            );
        }
        let total = begin
            .files
            .iter()
            .fold(0u64, |total, file| total.saturating_add(file.size));
        let batch_limit = if policy.accept_files {
            policy.max_bytes
        } else {
            policy.max_bytes.min(IMAGE_ONLY_MAX_BATCH_BYTES)
        };
        if total > batch_limit {
            return failure(
                id,
                "too_large",
                format!(
                    "The upload is larger than this server's limit of {}.",
                    format_bytes(batch_limit)
                ),
            );
        }

        let dir = match prepare_batch_dir(&policy, self.client_id, id, total) {
            Ok(dir) => dir,
            Err((code, message)) => {
                warn!(client_id = self.client_id, code, %message, "cannot stage upload");
                return failure(id, code, message);
            }
        };
        let files = begin
            .files
            .iter()
            .zip(names)
            .enumerate()
            .map(|(index, (file, name))| {
                StagedFile {
                    // Sanitized names never start with a dot, so this cannot collide.
                    partial_path: dir.join(format!(".{index}{PARTIAL_SUFFIX}")),
                    final_path: dir.join(name),
                    size: file.size,
                    written: 0,
                }
            })
            .collect();
        let mut batch = Batch {
            target,
            dir,
            files,
            current: 0,
            handle: None,
            received: 0,
        };
        if let Err(err) = complete_empty_files(&mut batch) {
            discard(batch);
            return failure(id, "io", format!("cannot stage upload: {err}"));
        }
        self.batches.insert(id, batch);
        ack(id, 0)
    }

    fn chunk(&mut self, chunk: EndpointUploadChunk) -> UploadControlOutcome {
        let id = chunk.id;
        let Some(batch) = self.batches.get_mut(&id) else {
            // Chunks still in flight after a failure or cancel.
            return UploadControlOutcome::Ignore;
        };
        match write_chunk(batch, &chunk) {
            Ok(received) => ack(id, received),
            Err((code, message)) => {
                if let Some(batch) = self.batches.remove(&id) {
                    discard(batch);
                }
                warn!(client_id = self.client_id, id, code, %message, "upload chunk rejected");
                failure(id, code, message)
            }
        }
    }

    fn end(&mut self, id: u64) -> UploadControlOutcome {
        let Some(batch) = self.batches.remove(&id) else {
            return UploadControlOutcome::Ignore;
        };
        if batch.current != batch.files.len() {
            discard(batch);
            return failure(id, "incomplete", "upload ended before every file arrived");
        }
        let paths = batch
            .files
            .iter()
            .map(|file| file.final_path.clone())
            .collect::<Vec<_>>();
        info!(
            client_id = self.client_id,
            id,
            files = paths.len(),
            bytes = batch.received,
            dir = %batch.dir.display(),
            "staged client upload"
        );
        UploadControlOutcome::Staged(StagedUpload {
            id,
            target: batch.target,
            paths,
        })
    }
}

impl Drop for UploadReceiver {
    fn drop(&mut self) {
        for (_, batch) in self.batches.drain() {
            discard(batch);
        }
    }
}

fn write_chunk(
    batch: &mut Batch,
    chunk: &EndpointUploadChunk,
) -> Result<u64, (&'static str, String)> {
    let index = chunk.file as usize;
    if index != batch.current || index >= batch.files.len() {
        return Err(("invalid", "upload chunk arrived out of order".into()));
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(&chunk.data)
        .map_err(|_| ("invalid", "upload chunk is not valid base64".to_owned()))?;
    let file = &mut batch.files[index];
    if chunk.offset != file.written
        || data.is_empty()
        || data.len() > UPLOAD_CHUNK_BYTES
        || file.written + data.len() as u64 > file.size
    {
        return Err((
            "invalid",
            "upload chunk does not match the announced file".into(),
        ));
    }
    let io_error = |err: io::Error| ("io", format!("cannot write upload: {err}"));
    if batch.handle.is_none() {
        batch.handle = Some(create_private_file(&file.partial_path).map_err(io_error)?);
    }
    if let Some(handle) = batch.handle.as_mut() {
        handle.write_all(&data).map_err(io_error)?;
    }
    file.written += data.len() as u64;
    batch.received += data.len() as u64;
    if file.written == file.size {
        batch.handle = None;
        if fs::symlink_metadata(&file.final_path).is_ok() {
            return Err((
                "io",
                format!("{} already exists", file.final_path.display()),
            ));
        }
        fs::rename(&file.partial_path, &file.final_path).map_err(io_error)?;
        batch.current += 1;
        complete_empty_files(batch).map_err(io_error)?;
    }
    Ok(batch.received)
}

fn complete_empty_files(batch: &mut Batch) -> io::Result<()> {
    while let Some(file) = batch.files.get(batch.current) {
        if file.size != 0 {
            break;
        }
        create_private_file(&file.final_path)?;
        batch.current += 1;
    }
    Ok(())
}

fn discard(batch: Batch) {
    drop(batch.handle);
    if let Err(err) = fs::remove_dir_all(&batch.dir) {
        if err.kind() != io::ErrorKind::NotFound {
            warn!(dir = %batch.dir.display(), err = %err, "failed to remove unfinished upload");
        }
    }
}

fn ack(id: u64, received: u64) -> UploadControlOutcome {
    upload_control_message(UPLOAD_ACK_KIND, &EndpointUploadAck { id, received })
        .map(UploadControlOutcome::Reply)
        .unwrap_or(UploadControlOutcome::Ignore)
}

fn failure(id: u64, code: &str, message: impl Into<String>) -> UploadControlOutcome {
    result_message(&EndpointUploadResult::failure(id, code, message))
        .map(UploadControlOutcome::Reply)
        .unwrap_or(UploadControlOutcome::Ignore)
}

fn prepare_batch_dir(
    policy: &ServerUploadPolicy,
    client_id: u64,
    id: u64,
    incoming: u64,
) -> Result<PathBuf, (&'static str, String)> {
    let io_error = |err: io::Error| ("io", format!("cannot create upload directory: {err}"));
    ensure_private_dir(&policy.dir).map_err(io_error)?;
    let staged = sweep_stale(&policy.dir, policy.retention);
    let quota = policy.max_bytes.saturating_mul(STAGED_TOTAL_FACTOR);
    if staged.saturating_add(incoming) > quota {
        return Err((
            "quota",
            format!(
                "This server already holds {} of uploads (limit {}). Older uploads are removed after server.upload_retention_hours.",
                format_bytes(staged),
                format_bytes(quota)
            ),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = policy
        .dir
        .join(format!("{BATCH_DIR_PREFIX}{now}-{client_id}-{id}"));
    crate::platform::create_private_dir(&dir).map_err(io_error)?;
    Ok(dir)
}

/// Remove expired staged uploads at server start, off the main loop.
pub(crate) fn sweep_at_startup() {
    let spawned = crate::thread_spawn::spawn_named("herdr-upload-sweep", || {
        let policy = crate::config::Config::load().config.server_upload_policy();
        sweep_stale(&policy.dir, policy.retention);
    });
    if let Err(err) = spawned {
        warn!(err = %err, "failed to start the upload sweep");
    }
}

fn is_batch_dir_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(BATCH_DIR_PREFIX) else {
        return false;
    };
    let parts = rest.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Delete expired batch directories and return the bytes still staged. A batch with a
/// partial file written within the retention window is still uploading and is kept.
fn sweep_stale(dir: &Path, retention: std::time::Duration) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let is_recent = |metadata: &fs::Metadata| {
        metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_none_or(|age| age <= retention)
    };
    let mut staged = 0u64;
    for entry in entries.flatten() {
        if !entry.file_name().to_str().is_some_and(is_batch_dir_name) {
            continue;
        }
        // `DirEntry::metadata` does not follow symlinks.
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let mut bytes = 0u64;
        let mut uploading = false;
        if let Ok(files) = fs::read_dir(entry.path()) {
            for file in files.flatten() {
                let Ok(file_metadata) = file.metadata() else {
                    continue;
                };
                bytes = bytes.saturating_add(file_metadata.len());
                let partial = file
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(PARTIAL_SUFFIX));
                uploading |= partial && is_recent(&file_metadata);
            }
        }
        if is_recent(&metadata) || uploading {
            staged = staged.saturating_add(bytes);
        } else {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    staged
}

/// Keep a readable name an agent can recognize, without characters that need quoting
/// or that could escape the batch directory.
pub(crate) fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let mut sanitized = base
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.starts_with('.') {
        sanitized.replace_range(0..1, "_");
    }
    if sanitized.len() > MAX_STAGED_NAME_BYTES {
        let extension = Path::new(&sanitized)
            .extension()
            .and_then(|extension| extension.to_str())
            .filter(|extension| extension.len() < 16)
            .map(|extension| format!(".{extension}"))
            .unwrap_or_default();
        sanitized.truncate(MAX_STAGED_NAME_BYTES - extension.len());
        sanitized.push_str(&extension);
    }
    if sanitized.trim_matches(['_', '.']).is_empty() {
        "upload".into()
    } else {
        sanitized
    }
}

fn unique_name(name: String, used: &mut Vec<String>) -> String {
    let mut candidate = name.clone();
    let mut counter = 1;
    // Case-insensitive, so `Shot.png` and `shot.PNG` stay distinct on macOS servers.
    while used
        .iter()
        .any(|used: &String| used.eq_ignore_ascii_case(&candidate))
    {
        let path = Path::new(&name);
        candidate = match (
            path.file_stem().and_then(|stem| stem.to_str()),
            path.extension().and_then(|extension| extension.to_str()),
        ) {
            (Some(stem), Some(extension)) => format!("{stem}-{counter}.{extension}"),
            _ => format!("{name}-{counter}"),
        };
        counter += 1;
    }
    used.push(candidate.clone());
    candidate
}

fn quote_path(path: &str) -> String {
    let safe = path
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '\\'));
    if safe {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}

fn format_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

/// Create the upload directory private, or accept an existing one this user owns.
/// An existing directory keeps its permissions (it may be one the user chose, such as
/// `~/Downloads`); each batch directory inside it is private regardless.
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    let existed = fs::symlink_metadata(dir).is_ok();
    if !existed {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Err(err) = crate::platform::create_private_dir(dir) {
            if err.kind() != io::ErrorKind::AlreadyExists {
                return Err(err);
            }
        }
    }
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "upload directory is not a directory: {}",
            dir.display()
        )));
    }
    if !crate::platform::owned_by_current_user(&metadata) {
        return Err(io::Error::other(format!(
            "upload directory is owned by another user: {}",
            dir.display()
        )));
    }
    Ok(())
}

fn create_private_file(path: &Path) -> io::Result<fs::File> {
    crate::platform::create_private_state_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::endpoint::{EndpointUploadFile, EndpointUploadTarget};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "herdr-upload-test-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            Self(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn receiver(dir: &Path, accept_files: bool, max_bytes: u64) -> UploadReceiver {
        let policy = ServerUploadPolicy {
            accept_files,
            max_bytes,
            retention: std::time::Duration::from_secs(3600),
            dir: dir.to_path_buf(),
        };
        UploadReceiver::with_policy_loader(9, Box::new(move || policy.clone()))
    }

    fn begin(id: u64, files: &[(&str, u64)]) -> String {
        serde_json::to_string(&EndpointUploadBegin {
            id,
            target: EndpointUploadTarget::Pane("w1:p1".into()),
            files: files
                .iter()
                .map(|(name, size)| EndpointUploadFile {
                    name: (*name).into(),
                    size: *size,
                })
                .collect(),
        })
        .unwrap()
    }

    fn chunk(id: u64, file: u32, offset: u64, bytes: &[u8]) -> String {
        serde_json::to_string(&EndpointUploadChunk {
            id,
            file,
            offset,
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
        .unwrap()
    }

    fn end(id: u64) -> String {
        serde_json::to_string(&EndpointUploadId { id }).unwrap()
    }

    fn reply(outcome: UploadControlOutcome) -> (String, String) {
        match outcome {
            UploadControlOutcome::Reply(ServerMessage::EndpointControl { kind, data }) => {
                (kind, data)
            }
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    fn failure_code(outcome: UploadControlOutcome) -> String {
        let (kind, data) = reply(outcome);
        assert_eq!(kind, UPLOAD_RESULT_KIND);
        let result: EndpointUploadResult = serde_json::from_str(&data).unwrap();
        assert!(!result.ok);
        result.code.unwrap()
    }

    #[test]
    fn a_multi_file_batch_is_staged_with_sanitized_names_and_acked_per_chunk() {
        let dir = TestDir::new("batch");
        let mut uploads = receiver(&dir.0, true, 1024);

        let (kind, data) = reply(uploads.handle(
            UPLOAD_BEGIN_KIND,
            &begin(
                1,
                &[("My Report.pdf", 5), ("../notes.txt", 0), ("shot.png", 2)],
            ),
        ));
        assert_eq!(kind, UPLOAD_ACK_KIND);
        assert_eq!(
            serde_json::from_str::<EndpointUploadAck>(&data)
                .unwrap()
                .received,
            0
        );

        let (_, data) = reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 0, 0, b"hel")));
        assert_eq!(
            serde_json::from_str::<EndpointUploadAck>(&data)
                .unwrap()
                .received,
            3
        );
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 0, 3, b"lo")));
        // The empty second file completes on its own; the third follows.
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 2, 0, b"ok")));

        let UploadControlOutcome::Staged(staged) = uploads.handle(UPLOAD_END_KIND, &end(1)) else {
            panic!("expected a staged batch");
        };
        let names = staged
            .paths
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, ["My_Report.pdf", "notes.txt", "shot.png"]);
        assert_eq!(fs::read(&staged.paths[0]).unwrap(), b"hello");
        assert_eq!(fs::read(&staged.paths[1]).unwrap(), b"");
        assert_eq!(fs::read(&staged.paths[2]).unwrap(), b"ok");
        let paste = staged.paste_text();
        assert_eq!(paste.matches(' ').count(), 2);
        assert!(paste.ends_with("shot.png"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&staged.paths[0]).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let mode = fs::metadata(&dir.0).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn non_image_files_need_the_server_owner_to_accept_uploads() {
        let dir = TestDir::new("disabled");
        let mut uploads = receiver(&dir.0, false, 1024);
        assert_eq!(
            failure_code(
                uploads.handle(UPLOAD_BEGIN_KIND, &begin(1, &[("a.png", 1), ("b.pdf", 1)]))
            ),
            "files_disabled"
        );
        let (kind, _) = reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(2, &[("a.PNG", 1)])));
        assert_eq!(kind, UPLOAD_ACK_KIND);
    }

    #[test]
    fn oversized_and_malformed_uploads_fail_without_leaving_files() {
        let dir = TestDir::new("reject");
        let mut uploads = receiver(&dir.0, true, 4);
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_BEGIN_KIND, &begin(1, &[("a.pdf", 5)]))),
            "too_large"
        );
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(2, &[("a.pdf", 4)])));
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(2, 0, 1, b"x"))),
            "invalid"
        );
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(3, &[("a.pdf", 4)])));
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(3, 0, 0, b"12345"))),
            "invalid"
        );
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(4, &[("a.pdf", 4)])));
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(4, 0, 0, b"12")));
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_END_KIND, &end(4))),
            "incomplete"
        );
        assert!(matches!(
            uploads.handle(UPLOAD_CHUNK_KIND, &chunk(4, 0, 2, b"34")),
            UploadControlOutcome::Ignore
        ));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }

    #[test]
    fn disconnecting_or_cancelling_discards_unfinished_batches() {
        let dir = TestDir::new("discard");
        let mut uploads = receiver(&dir.0, true, 1024);
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(1, &[("a.pdf", 4)])));
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 0, 0, b"12")));
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(2, &[("b.pdf", 4)])));
        uploads.handle(UPLOAD_CANCEL_KIND, &end(1));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        drop(uploads);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }

    #[test]
    fn staged_batches_survive_the_receiver() {
        let dir = TestDir::new("persist");
        let mut uploads = receiver(&dir.0, true, 1024);
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(1, &[("a.pdf", 1)])));
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 0, 0, b"x")));
        let UploadControlOutcome::Staged(staged) = uploads.handle(UPLOAD_END_KIND, &end(1)) else {
            panic!("expected a staged batch");
        };
        drop(uploads);
        assert!(staged.paths[0].exists());
    }

    #[cfg(unix)] // Setting a directory's mtime through `File` needs Unix semantics.
    #[test]
    fn sweeping_removes_only_expired_herdr_batches_and_reports_what_remains() {
        let dir = TestDir::new("sweep");
        let old = SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
        let age = |path: &Path| {
            fs::File::open(path).unwrap().set_modified(old).unwrap();
        };
        let expired = dir.0.join("herdr-upload-1-2-3");
        let uploading = dir.0.join("herdr-upload-4-5-6");
        let fresh = dir.0.join("herdr-upload-7-8-9");
        let user_dated = dir.0.join("2024-01-15");
        for path in [&expired, &uploading, &fresh, &user_dated] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(expired.join("a.pdf"), b"12345").unwrap();
        fs::write(uploading.join(".0.partial"), b"123").unwrap();
        fs::write(fresh.join("b.pdf"), b"1").unwrap();
        for path in [&expired, &expired.join("a.pdf"), &uploading, &user_dated] {
            age(path);
        }

        let staged = sweep_stale(&dir.0, std::time::Duration::from_secs(60 * 60));
        assert!(!expired.exists());
        assert!(
            uploading.exists(),
            "a recently written partial file keeps its batch"
        );
        assert!(fresh.exists());
        assert!(user_dated.exists(), "only herdr batch names are ever swept");
        assert_eq!(staged, 4);
    }

    #[test]
    fn staged_uploads_are_capped_in_total() {
        let dir = TestDir::new("quota");
        let mut uploads = receiver(&dir.0, true, 4);
        for id in 1..=4 {
            reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(id, &[("a.pdf", 4)])));
            reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(id, 0, 0, b"1234")));
            assert!(matches!(
                uploads.handle(UPLOAD_END_KIND, &end(id)),
                UploadControlOutcome::Staged(_)
            ));
        }
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_BEGIN_KIND, &begin(5, &[("a.pdf", 1)]))),
            "quota"
        );
    }

    #[test]
    fn image_only_servers_check_the_sanitized_name_and_cap_each_drop() {
        let dir = TestDir::new("image-only");
        let mut uploads = receiver(&dir.0, false, u64::MAX / 8);
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_BEGIN_KIND, &begin(1, &[("a.png/", 1)]))),
            "files_disabled"
        );
        assert_eq!(
            failure_code(uploads.handle(
                UPLOAD_BEGIN_KIND,
                &begin(2, &[("a.png", IMAGE_ONLY_MAX_BATCH_BYTES), ("b.png", 1)])
            )),
            "too_large"
        );
    }

    #[test]
    fn an_unknown_target_kind_is_rejected() {
        let dir = TestDir::new("target");
        let mut uploads = receiver(&dir.0, true, 1024);
        let data =
            r#"{"id":1,"target":{"kind":"window","id":"x"},"files":[{"name":"a.pdf","size":1}]}"#;
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_BEGIN_KIND, data)),
            "invalid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_upload_directory_is_rejected() {
        let dir = TestDir::new("symlink");
        let target = TestDir::new("symlink-target");
        fs::create_dir_all(&target.0).unwrap();
        fs::create_dir_all(&dir.0).unwrap();
        let link = dir.0.join("uploads");
        std::os::unix::fs::symlink(&target.0, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
    }

    #[test]
    fn names_differing_only_in_case_or_looking_like_partials_do_not_collide() {
        let dir = TestDir::new("collide");
        let mut uploads = receiver(&dir.0, true, 1024);
        reply(uploads.handle(
            UPLOAD_BEGIN_KIND,
            &begin(
                1,
                &[("Shot.PNG", 1), ("shot.png", 1), ("x.partial", 0), ("x", 1)],
            ),
        ));
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 0, 0, b"A")));
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 1, 0, b"b")));
        reply(uploads.handle(UPLOAD_CHUNK_KIND, &chunk(1, 3, 0, b"x")));
        let UploadControlOutcome::Staged(staged) = uploads.handle(UPLOAD_END_KIND, &end(1)) else {
            panic!("expected a staged batch");
        };
        assert_eq!(fs::read(&staged.paths[0]).unwrap(), b"A");
        assert_eq!(fs::read(&staged.paths[1]).unwrap(), b"b");
        assert!(staged.paths[1].ends_with("shot-1.png"));
        assert_eq!(fs::read(&staged.paths[3]).unwrap(), b"x");
    }

    #[test]
    fn a_malformed_control_with_a_readable_id_fails_that_upload() {
        let dir = TestDir::new("malformed");
        let mut uploads = receiver(&dir.0, true, 1024);
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_BEGIN_KIND, r#"{"id":3,"files":"nope"}"#)),
            "invalid"
        );
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(4, &[("a.pdf", 2)])));
        assert_eq!(
            failure_code(uploads.handle(UPLOAD_CHUNK_KIND, r#"{"id":4,"data":1}"#)),
            "invalid"
        );
        assert!(matches!(
            uploads.handle(UPLOAD_BEGIN_KIND, "not json"),
            UploadControlOutcome::Ignore
        ));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_upload_directory_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("existing");
        fs::create_dir_all(&dir.0).unwrap();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let mut uploads = receiver(&dir.0, true, 1024);
        reply(uploads.handle(UPLOAD_BEGIN_KIND, &begin(1, &[("a.pdf", 1)])));
        let mode = fs::metadata(&dir.0).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let batch = fs::read_dir(&dir.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mode = fs::metadata(batch).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn file_names_are_sanitized_and_deduplicated() {
        assert_eq!(
            sanitize_file_name("Screenshot 2026\u{202f}PM.png"),
            "Screenshot_2026_PM.png"
        );
        assert_eq!(sanitize_file_name("..\\..\\evil.sh"), "evil.sh");
        assert_eq!(sanitize_file_name(".env"), "_env");
        assert_eq!(sanitize_file_name("///"), "upload");
        let long = format!("{}.pdf", "a".repeat(300));
        let sanitized = sanitize_file_name(&long);
        assert_eq!(sanitized.len(), MAX_STAGED_NAME_BYTES);
        assert!(sanitized.ends_with(".pdf"));
        let mut used = Vec::new();
        assert_eq!(unique_name("a.pdf".into(), &mut used), "a.pdf");
        assert_eq!(unique_name("a.pdf".into(), &mut used), "a-1.pdf");
        assert_eq!(unique_name("a.pdf".into(), &mut used), "a-2.pdf");
    }

    #[test]
    fn paste_text_quotes_paths_that_need_it() {
        let staged = StagedUpload {
            id: 1,
            target: ClientClipboardImageTarget::DirectTerminal,
            paths: vec![
                PathBuf::from("/tmp/a.pdf"),
                PathBuf::from("/my dir/b'c.pdf"),
            ],
        };
        assert_eq!(staged.paste_text(), "/tmp/a.pdf '/my dir/b'\\''c.pdf'");
    }

    #[test]
    fn capabilities_follow_the_server_owner_setting() {
        let mut policy = crate::config::Config::default().server_upload_policy();
        if cfg!(unix) {
            assert_eq!(advertised_capabilities(&policy), [UPLOAD_CAPABILITY]);
            policy.accept_files = true;
            assert_eq!(
                advertised_capabilities(&policy),
                [UPLOAD_CAPABILITY, UPLOAD_FILES_CAPABILITY]
            );
        } else {
            assert!(advertised_capabilities(&policy).is_empty());
        }
    }
}
