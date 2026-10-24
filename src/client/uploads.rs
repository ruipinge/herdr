//! Upload files dropped onto a remote pane, then let the server paste the staged paths.
//!
//! Servers that advertise the `upload` capability receive files as small base64 chunks
//! over named endpoint controls. The endpoint writer is FIFO, so at most
//! [`UPLOAD_WINDOW_BYTES`] of unacknowledged upload data can queue ahead of a keystroke
//! or health check, and no frame approaches the writer's stall timeout. Older servers
//! keep the single-frame `ClipboardImage` bridge for one image at a time.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use tracing::{info, warn};

use crate::config::{ClientUploadDecision, ClientUploadPolicy};
use crate::protocol::endpoint::{
    EndpointUploadAck, EndpointUploadBegin, EndpointUploadChunk, EndpointUploadFile,
    EndpointUploadId, EndpointUploadResult, EndpointUploadTarget, UPLOAD_BEGIN_KIND,
    UPLOAD_CANCEL_KIND, UPLOAD_CAPABILITY, UPLOAD_CHUNK_BYTES, UPLOAD_CHUNK_KIND, UPLOAD_END_KIND,
    UPLOAD_FILES_CAPABILITY,
};
use crate::protocol::{ClientClipboardImageTarget, ClientMessage, MAX_CLIPBOARD_IMAGE_PAYLOAD};

use super::endpoint::{ClientEndpointId, EndpointRegistry, EndpointSendOutcome};

/// Unacknowledged bytes allowed in flight for the active upload: about 340 KB on the
/// wire, a fraction of a second of input delay on a typical uplink.
const UPLOAD_WINDOW_BYTES: u64 = 4 * UPLOAD_CHUNK_BYTES as u64;
/// Longest server-provided text shown in a notice.
const MAX_NOTICE_TEXT_CHARS: usize = 512;
/// An upload without server progress for this long is cancelled.
const UPLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Drops waiting behind the active upload.
const MAX_QUEUED_UPLOADS: usize = 4;
/// Uploads at least this large show progress and a completion notice.
const NOTICEABLE_UPLOAD_BYTES: u64 = 1024 * 1024;
const PROGRESS_NOTICE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UploadNoticeTone {
    Progress,
    Done,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UploadNotice {
    pub(crate) tone: UploadNoticeTone,
    pub(crate) title: String,
    pub(crate) body: String,
}

#[derive(Debug)]
pub(super) enum DropHandling {
    /// Not bridged; the drop continues as typed text.
    Ignored,
    /// The server predates uploads: send this one image with `ClipboardImage`.
    LegacyImage(crate::platform::ClipboardImage),
    /// Accepted by the uploader; the server pastes the staged paths when done.
    Accepted,
}

/// A dropped file, opened when the drop was accepted so the bytes sent are the file the
/// policy approved, even if its path is replaced before the upload starts.
#[derive(Debug)]
struct LocalFile {
    name: String,
    size: u64,
    handle: Option<fs::File>,
}

struct PendingUpload {
    endpoint_id: ClientEndpointId,
    generation: u64,
    target: ClientClipboardImageTarget,
    files: Vec<LocalFile>,
}

struct ActiveUpload {
    id: u64,
    endpoint_id: ClientEndpointId,
    generation: u64,
    files: Vec<LocalFile>,
    file_index: usize,
    file_offset: u64,
    total: u64,
    sent: u64,
    acked: u64,
    ended: bool,
    last_progress: Instant,
    last_notice: Option<Instant>,
}

impl ActiveUpload {
    fn label(&self) -> String {
        files_label(&self.files)
    }
}

pub(super) struct ClientUploads {
    policy: ClientUploadPolicy,
    next_id: u64,
    active: Option<ActiveUpload>,
    queued: VecDeque<PendingUpload>,
    /// An upload whose bytes all went out but whose result did not arrive in time.
    unconfirmed: Option<(ClientEndpointId, u64)>,
    notices: Vec<UploadNotice>,
}

impl ClientUploads {
    pub(super) fn new(policy: ClientUploadPolicy) -> Self {
        Self {
            policy,
            next_id: 1,
            active: None,
            queued: VecDeque::new(),
            unconfirmed: None,
            notices: Vec::new(),
        }
    }

    pub(super) fn set_policy(&mut self, policy: ClientUploadPolicy) {
        self.policy = policy;
    }

    pub(super) fn take_notices(&mut self) -> Vec<UploadNotice> {
        std::mem::take(&mut self.notices)
    }

    /// Decide what to do with absolute paths a terminal pasted for a drop on a remote pane.
    pub(super) fn handle_drop(
        &mut self,
        paths: Vec<PathBuf>,
        target: ClientClipboardImageTarget,
        endpoints: &mut EndpointRegistry,
        now: Instant,
    ) -> DropHandling {
        let mut files = Vec::with_capacity(paths.len());
        let mut has_non_image = false;
        let mut legacy_extension = None;
        for path in paths {
            // Decide on the resolved target too, so a symlink cannot smuggle a file from a
            // hidden directory such as `~/.ssh` past the policy. Open the resolved path,
            // which has no symlinks left to swap.
            let Ok(resolved) = fs::canonicalize(&path) else {
                return DropHandling::Ignored;
            };
            match (self.policy.decide(&path), self.policy.decide(&resolved)) {
                (ClientUploadDecision::Skip, _) | (_, ClientUploadDecision::Skip) => {
                    return DropHandling::Ignored;
                }
                (ClientUploadDecision::Image, ClientUploadDecision::Image) => {
                    legacy_extension = legacy_image_extension(&path);
                }
                _ => has_non_image = true,
            }
            let Ok(handle) = fs::File::open(&resolved) else {
                return DropHandling::Ignored;
            };
            let Ok(metadata) = handle.metadata() else {
                return DropHandling::Ignored;
            };
            if !metadata.is_file() {
                return DropHandling::Ignored;
            }
            files.push(LocalFile {
                name: file_name(&path),
                size: metadata.len(),
                handle: Some(handle),
            });
        }

        let endpoint_id = endpoints.active_id().clone();
        let Some(connection) = endpoints.connection(&endpoint_id) else {
            return DropHandling::Ignored;
        };
        let generation = connection.generation;
        let negotiation = &connection.negotiation;
        if !negotiation.supports_capability(UPLOAD_CAPABILITY) {
            if let ([file], Some(extension)) = (files.as_mut_slice(), legacy_extension) {
                if !has_non_image {
                    return file
                        .handle
                        .take()
                        .and_then(|handle| read_legacy_image(handle, extension))
                        .map(DropHandling::LegacyImage)
                        .unwrap_or(DropHandling::Ignored);
                }
            }
            self.notify(
                UploadNoticeTone::Failed,
                "Upload unavailable",
                if has_non_image {
                    "This server cannot receive files. Update Herdr on it; Windows servers do not accept uploads yet."
                } else {
                    "This server bridges one image at a time. Update Herdr on it to drop several at once."
                },
            );
            return DropHandling::Ignored;
        }
        if has_non_image && !negotiation.supports_capability(UPLOAD_FILES_CAPABILITY) {
            self.notify(
                UploadNoticeTone::Failed,
                "Upload unavailable",
                "This server only accepts image uploads. Set server.accept_uploads = true in its config, then reconnect.",
            );
            return DropHandling::Ignored;
        }
        if let Some(file) = files.iter().find(|file| file.size > self.policy.max_bytes) {
            self.notify(
                UploadNoticeTone::Failed,
                "File too large",
                format!(
                    "{} is larger than remote.upload_max_bytes ({}); pasted its local path instead.",
                    file.name,
                    format_bytes(self.policy.max_bytes)
                ),
            );
            return DropHandling::Ignored;
        }
        if self.queued.len() >= MAX_QUEUED_UPLOADS {
            self.notify(
                UploadNoticeTone::Failed,
                "Upload busy",
                "Too many uploads are waiting; drop again when the current one finishes.",
            );
            return DropHandling::Ignored;
        }

        self.queued.push_back(PendingUpload {
            endpoint_id,
            generation,
            target,
            files,
        });
        self.pump(endpoints, now);
        DropHandling::Accepted
    }

    pub(super) fn receive_ack(
        &mut self,
        endpoint_id: &ClientEndpointId,
        ack: EndpointUploadAck,
        endpoints: &mut EndpointRegistry,
        now: Instant,
    ) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.id != ack.id || &active.endpoint_id != endpoint_id {
            return;
        }
        if ack.received > active.acked {
            active.acked = ack.received.min(active.sent);
            active.last_progress = now;
        }
        if active.total >= NOTICEABLE_UPLOAD_BYTES
            && !active.ended
            && active
                .last_notice
                .is_none_or(|last| now.duration_since(last) >= PROGRESS_NOTICE_INTERVAL)
        {
            active.last_notice = Some(now);
            let percent = active.acked.saturating_mul(100) / active.total.max(1);
            let title = format!("Uploading {}", active.label());
            let body = format!("{percent}% of {}", format_bytes(active.total));
            self.notify(UploadNoticeTone::Progress, title, body);
        }
        self.pump(endpoints, now);
    }

    pub(super) fn receive_result(
        &mut self,
        endpoint_id: &ClientEndpointId,
        result: EndpointUploadResult,
        endpoints: &mut EndpointRegistry,
        now: Instant,
    ) {
        if self.unconfirmed.as_ref() == Some(&(endpoint_id.clone(), result.id)) {
            self.unconfirmed = None;
            if result.ok {
                self.notify_not_pasted(&result);
            }
            return;
        }
        let Some(active) = self.active.as_ref() else {
            return;
        };
        if active.id != result.id || &active.endpoint_id != endpoint_id {
            return;
        }
        let Some(active) = self.active.take() else {
            return;
        };
        if result.ok {
            info!(
                id = active.id,
                files = result.paths.len(),
                pasted = result.pasted,
                "upload finished"
            );
            if !result.pasted {
                self.notify_not_pasted(&result);
            } else if active.total >= NOTICEABLE_UPLOAD_BYTES {
                self.notify(
                    UploadNoticeTone::Done,
                    format!("Uploaded {}", active.label()),
                    format_bytes(active.total),
                );
            }
        } else {
            warn!(id = active.id, code = ?result.code, message = ?result.message, "upload rejected");
            self.notify(
                UploadNoticeTone::Failed,
                "Upload failed",
                truncate_notice_text(
                    result
                        .message
                        .unwrap_or_else(|| "The server rejected the upload.".into()),
                ),
            );
        }
        self.pump(endpoints, now);
    }

    fn notify_not_pasted(&mut self, result: &EndpointUploadResult) {
        let reason = result
            .message
            .as_deref()
            .unwrap_or("The target pane changed during the upload.");
        self.notify(
            UploadNoticeTone::Done,
            "Uploaded, not pasted",
            truncate_notice_text(format!("{reason} Staged at {}", result.paths.join(" "))),
        );
    }

    /// Abandon uploads whose endpoint went away or stopped acknowledging, then start
    /// queued work.
    pub(super) fn tick(&mut self, endpoints: &mut EndpointRegistry, now: Instant) {
        if let Some(active) = self.active.as_ref() {
            let connected = endpoints
                .connection(&active.endpoint_id)
                .is_some_and(|connection| connection.generation == active.generation);
            if !connected {
                self.fail_active(endpoints, "The connection to the server was lost.", false);
            } else if now.duration_since(active.last_progress) > UPLOAD_STALL_TIMEOUT {
                if active.ended {
                    // Every byte arrived; the server may still paste, so do not cancel, and
                    // still report a late result.
                    self.unconfirmed = Some((active.endpoint_id.clone(), active.id));
                    self.fail_active(
                        endpoints,
                        "The server did not confirm the upload. It may still appear in the pane.",
                        false,
                    );
                } else {
                    self.fail_active(endpoints, "The server stopped responding.", true);
                }
            }
        }
        self.pump(endpoints, now);
    }

    pub(super) fn is_idle(&self) -> bool {
        self.active.is_none() && self.queued.is_empty()
    }

    fn pump(&mut self, endpoints: &mut EndpointRegistry, now: Instant) {
        loop {
            if self.active.is_none() && !self.start_next(endpoints, now) {
                return;
            }
            match self.send_window(endpoints) {
                Ok(()) => return,
                Err(message) => self.fail_active(endpoints, &message, true),
            }
        }
    }

    fn start_next(&mut self, endpoints: &mut EndpointRegistry, now: Instant) -> bool {
        while let Some(pending) = self.queued.pop_front() {
            let connected = endpoints
                .connection(&pending.endpoint_id)
                .is_some_and(|connection| connection.generation == pending.generation);
            if !connected {
                self.notify(
                    UploadNoticeTone::Failed,
                    "Upload failed",
                    "The connection to the server was lost.",
                );
                continue;
            }
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let begin = EndpointUploadBegin {
                id,
                target: EndpointUploadTarget::from(pending.target),
                files: pending
                    .files
                    .iter()
                    .map(|file| EndpointUploadFile {
                        name: file.name.clone(),
                        size: file.size,
                    })
                    .collect(),
            };
            let total = pending.files.iter().map(|file| file.size).sum();
            if !send_control(endpoints, &pending.endpoint_id, UPLOAD_BEGIN_KIND, &begin) {
                self.notify(
                    UploadNoticeTone::Failed,
                    "Upload failed",
                    "The connection to the server was lost.",
                );
                continue;
            }
            info!(
                id,
                files = pending.files.len(),
                bytes = total,
                "uploading dropped files"
            );
            self.active = Some(ActiveUpload {
                id,
                endpoint_id: pending.endpoint_id,
                generation: pending.generation,
                files: pending.files,
                file_index: 0,
                file_offset: 0,
                total,
                sent: 0,
                acked: 0,
                ended: false,
                last_progress: now,
                last_notice: None,
            });
            return true;
        }
        false
    }

    /// Send chunks until the window is full, then `end` after the last byte.
    fn send_window(&mut self, endpoints: &mut EndpointRegistry) -> Result<(), String> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        while !active.ended && active.sent - active.acked < UPLOAD_WINDOW_BYTES {
            while let Some(file) = active.files.get_mut(active.file_index) {
                if active.file_offset < file.size {
                    break;
                }
                file.handle = None;
                active.file_index += 1;
                active.file_offset = 0;
            }
            let Some(file) = active.files.get_mut(active.file_index) else {
                let end = EndpointUploadId { id: active.id };
                if !send_control(endpoints, &active.endpoint_id, UPLOAD_END_KIND, &end) {
                    return Err("The connection to the server was lost.".into());
                }
                active.ended = true;
                return Ok(());
            };
            let remaining = file.size - active.file_offset;
            let mut buffer = vec![0; remaining.min(UPLOAD_CHUNK_BYTES as u64) as usize];
            let read = match file.handle.as_mut() {
                Some(handle) => read_full(handle, &mut buffer)
                    .map_err(|err| format!("Cannot read {}: {err}", file.name))?,
                None => 0,
            };
            if read == 0 {
                return Err(format!("{} changed while it was uploading.", file.name));
            }
            let chunk = EndpointUploadChunk {
                id: active.id,
                file: active.file_index as u32,
                offset: active.file_offset,
                data: base64::engine::general_purpose::STANDARD.encode(&buffer[..read]),
            };
            if !send_control(endpoints, &active.endpoint_id, UPLOAD_CHUNK_KIND, &chunk) {
                return Err("The connection to the server was lost.".into());
            }
            active.file_offset += read as u64;
            active.sent += read as u64;
        }
        Ok(())
    }

    fn fail_active(&mut self, endpoints: &mut EndpointRegistry, message: &str, cancel: bool) {
        let Some(active) = self.active.take() else {
            return;
        };
        warn!(id = active.id, %message, "upload abandoned");
        if cancel {
            let cancel = EndpointUploadId { id: active.id };
            send_control(endpoints, &active.endpoint_id, UPLOAD_CANCEL_KIND, &cancel);
        }
        self.notify(UploadNoticeTone::Failed, "Upload failed", message);
    }

    fn notify(
        &mut self,
        tone: UploadNoticeTone,
        title: impl Into<String>,
        body: impl Into<String>,
    ) {
        self.notices.push(UploadNotice {
            tone,
            title: title.into(),
            body: body.into(),
        });
    }
}

/// Bridge a Unix terminal drop. Returns true when the input was consumed.
#[cfg(unix)]
pub(super) fn bridge_terminal_drop(
    state: &mut super::state::ClientState,
    endpoints: &mut EndpointRegistry,
    target: ClientClipboardImageTarget,
    data: &[u8],
    now: Instant,
) -> Result<bool, super::ClientError> {
    let Some(paths) = super::drop_paths::dropped_paths_from_terminal_input(data) else {
        return Ok(false);
    };
    bridge_dropped_paths(state, endpoints, target, paths, now)
}

/// Bridge a Windows drop delivered as a single paste event.
#[cfg(windows)]
pub(super) fn bridge_client_events_drop(
    state: &mut super::state::ClientState,
    endpoints: &mut EndpointRegistry,
    target: ClientClipboardImageTarget,
    events: &[crate::protocol::ClientInputEvent],
    now: Instant,
) -> Result<bool, super::ClientError> {
    let [crate::protocol::ClientInputEvent::Paste { text }] = events else {
        return Ok(false);
    };
    let Some(paths) = super::drop_paths::dropped_paths_from_paste_text(text) else {
        return Ok(false);
    };
    bridge_dropped_paths(state, endpoints, target, paths, now)
}

fn bridge_dropped_paths(
    state: &mut super::state::ClientState,
    endpoints: &mut EndpointRegistry,
    target: ClientClipboardImageTarget,
    paths: Vec<PathBuf>,
    now: Instant,
) -> Result<bool, super::ClientError> {
    let handled = match state
        .uploads
        .handle_drop(paths, target.clone(), endpoints, now)
    {
        DropHandling::Ignored => false,
        DropHandling::LegacyImage(image) => {
            super::clipboard_images::write_remote_image_to_server(
                endpoints,
                target,
                image,
                "file drop",
            )?;
            true
        }
        DropHandling::Accepted => true,
    };
    present_upload_notices(state);
    Ok(handled)
}

/// Show pending upload notices in the client shell, or log them in direct-terminal mode.
pub(super) fn present_upload_notices(state: &mut super::state::ClientState) {
    let notices = state.uploads.take_notices();
    if notices.is_empty() {
        return;
    }
    let Some(shell) = state.shell.as_mut() else {
        for notice in notices {
            info!(title = %notice.title, body = %notice.body, "upload notice");
        }
        return;
    };
    let mut changed = false;
    for notice in notices {
        changed |= shell.receive_upload_notice(notice);
    }
    if changed {
        if let Some(frame) = shell.compose(state.reported_size.0, state.reported_size.1) {
            state.present_frame(frame);
        }
    }
}

fn send_control<T: serde::Serialize>(
    endpoints: &mut EndpointRegistry,
    endpoint_id: &ClientEndpointId,
    kind: &str,
    payload: &T,
) -> bool {
    let Ok(data) = serde_json::to_string(payload) else {
        return false;
    };
    let message = ClientMessage::EndpointControl {
        kind: kind.into(),
        data,
    };
    endpoints.send_to(endpoint_id, &message) == EndpointSendOutcome::Sent
}

fn read_full(handle: &mut fs::File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match handle.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn legacy_image_extension(path: &Path) -> Option<&'static str> {
    Some(
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "png" => "png",
            "jpg" | "jpeg" => "jpg",
            "gif" => "gif",
            "webp" => "webp",
            "bmp" => "bmp",
            _ => return None,
        },
    )
}

fn read_legacy_image(
    file: fs::File,
    extension: &'static str,
) -> Option<crate::platform::ClipboardImage> {
    match crate::platform::read_limited_reader(file, MAX_CLIPBOARD_IMAGE_PAYLOAD).ok()? {
        crate::platform::LimitedRead::Complete(bytes) => {
            Some(crate::platform::ClipboardImage { bytes, extension })
        }
        crate::platform::LimitedRead::Empty => None,
        crate::platform::LimitedRead::Oversized => {
            warn!(
                max = MAX_CLIPBOARD_IMAGE_PAYLOAD,
                "local image file drop is too large to bridge"
            );
            None
        }
    }
}

fn truncate_notice_text(text: String) -> String {
    if text.chars().count() <= MAX_NOTICE_TEXT_CHARS {
        return text;
    }
    let mut truncated = text.chars().take(MAX_NOTICE_TEXT_CHARS).collect::<String>();
    truncated.push('…');
    truncated
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload".into())
}

fn files_label(files: &[LocalFile]) -> String {
    match files {
        [file] => file.name.clone(),
        files => format!("{} files", files.len()),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::client::endpoint::{EndpointNegotiation, EndpointTransport};

    struct RecordingTransport(Arc<Mutex<Vec<ClientMessage>>>);

    impl EndpointTransport for RecordingTransport {
        fn send(&mut self, message: &ClientMessage) -> io::Result<()> {
            self.0.lock().unwrap().push(message.clone());
            Ok(())
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "herdr-client-upload-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn registry(capabilities: &[&str]) -> (EndpointRegistry, Arc<Mutex<Vec<ClientMessage>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let registry = EndpointRegistry::new(
            RecordingTransport(sent.clone()),
            1,
            EndpointNegotiation::new(
                Vec::new(),
                capabilities
                    .iter()
                    .map(|capability| (*capability).into())
                    .collect(),
            ),
        );
        (registry, sent)
    }

    fn uploads(extensions: &[&str]) -> ClientUploads {
        let mut config = crate::config::Config::default();
        config.remote.upload_extensions = extensions.iter().map(|entry| (*entry).into()).collect();
        ClientUploads::new(config.client_upload_policy())
    }

    fn controls(sent: &Arc<Mutex<Vec<ClientMessage>>>) -> Vec<(String, String)> {
        sent.lock()
            .unwrap()
            .drain(..)
            .filter_map(|message| match message {
                ClientMessage::EndpointControl { kind, data } => Some((kind, data)),
                _ => None,
            })
            .collect()
    }

    fn target() -> ClientClipboardImageTarget {
        ClientClipboardImageTarget::Pane("w1:p1".into())
    }

    #[test]
    fn old_servers_get_one_image_through_the_legacy_bridge() {
        let dir = TempDir::new("legacy");
        let image = dir.file("shot.png", b"png-bytes");
        let (mut endpoints, _) = registry(&[]);
        let mut uploads = uploads(&[]);
        let DropHandling::LegacyImage(bridged) = uploads.handle_drop(
            vec![image.clone()],
            target(),
            &mut endpoints,
            Instant::now(),
        ) else {
            panic!("expected the legacy image bridge");
        };
        assert_eq!(bridged.bytes, b"png-bytes");
        assert_eq!(bridged.extension, "png");
        assert!(matches!(
            uploads.handle_drop(
                vec![image.clone(), image],
                target(),
                &mut endpoints,
                Instant::now()
            ),
            DropHandling::Ignored
        ));
    }

    #[test]
    fn files_need_the_client_allow_list() {
        let dir = TempDir::new("allow");
        let pdf = dir.file("doc.pdf", b"pdf");
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY, UPLOAD_FILES_CAPABILITY]);
        let mut uploads = uploads(&[]);
        assert!(matches!(
            uploads.handle_drop(vec![pdf], target(), &mut endpoints, Instant::now()),
            DropHandling::Ignored
        ));
        assert!(uploads.take_notices().is_empty());
        assert!(controls(&sent).is_empty());
    }

    #[test]
    fn files_need_the_server_owner_to_accept_them() {
        let dir = TempDir::new("server-off");
        let pdf = dir.file("doc.pdf", b"pdf");
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY]);
        let mut uploads = uploads(&["pdf"]);
        assert!(matches!(
            uploads.handle_drop(vec![pdf], target(), &mut endpoints, Instant::now()),
            DropHandling::Ignored
        ));
        let notices = uploads.take_notices();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].body.contains("server.accept_uploads"));
        assert!(controls(&sent).is_empty());
    }

    #[test]
    fn missing_files_and_directories_stay_typed_text() {
        let dir = TempDir::new("missing");
        let (mut endpoints, _) = registry(&[UPLOAD_CAPABILITY, UPLOAD_FILES_CAPABILITY]);
        let mut uploads = uploads(&["*"]);
        assert!(matches!(
            uploads.handle_drop(
                vec![dir.0.join("nope.pdf")],
                target(),
                &mut endpoints,
                Instant::now()
            ),
            DropHandling::Ignored
        ));
        assert!(matches!(
            uploads.handle_drop(
                vec![dir.0.clone()],
                target(),
                &mut endpoints,
                Instant::now()
            ),
            DropHandling::Ignored
        ));
    }

    #[test]
    fn oversized_files_are_refused_with_a_notice() {
        let dir = TempDir::new("large");
        let pdf = dir.file("doc.pdf", b"12345");
        let (mut endpoints, _) = registry(&[UPLOAD_CAPABILITY, UPLOAD_FILES_CAPABILITY]);
        let mut config = crate::config::Config::default();
        config.remote.upload_extensions = vec!["pdf".into()];
        config.remote.upload_max_bytes = 4;
        let mut uploads = ClientUploads::new(config.client_upload_policy());
        assert!(matches!(
            uploads.handle_drop(vec![pdf], target(), &mut endpoints, Instant::now()),
            DropHandling::Ignored
        ));
        assert_eq!(uploads.take_notices()[0].title, "File too large");
    }

    #[test]
    fn uploads_stream_within_the_ack_window_and_end_after_the_last_byte() {
        let dir = TempDir::new("stream");
        // Above NOTICEABLE_UPLOAD_BYTES so completion is reported, and not a whole
        // number of chunks so the tail chunk is short.
        let big = vec![7u8; NOTICEABLE_UPLOAD_BYTES as usize + UPLOAD_CHUNK_BYTES + 10];
        let first = dir.file("big.bin", &big);
        let second = dir.file("small.png", b"png");
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY, UPLOAD_FILES_CAPABILITY]);
        let mut uploads = uploads(&["bin"]);
        let now = Instant::now();
        assert!(matches!(
            uploads.handle_drop(vec![first, second], target(), &mut endpoints, now),
            DropHandling::Accepted
        ));

        let sent_now = controls(&sent);
        assert_eq!(sent_now[0].0, UPLOAD_BEGIN_KIND);
        let begin: EndpointUploadBegin = serde_json::from_str(&sent_now[0].1).unwrap();
        assert_eq!(begin.files.len(), 2);
        assert_eq!(begin.files[0].size, big.len() as u64);
        let chunks = sent_now[1..]
            .iter()
            .map(|(kind, data)| {
                assert_eq!(kind, UPLOAD_CHUNK_KIND);
                serde_json::from_str::<EndpointUploadChunk>(data).unwrap()
            })
            .collect::<Vec<_>>();
        // The window bounds unacknowledged bytes.
        assert_eq!(chunks.len(), 4);

        let endpoint = ClientEndpointId::Local;
        let mut received = 0;
        let mut all = chunks;
        let mut ended = false;
        while !ended {
            received += 4 * UPLOAD_CHUNK_BYTES as u64;
            uploads.receive_ack(
                &endpoint,
                EndpointUploadAck {
                    id: begin.id,
                    received,
                },
                &mut endpoints,
                now,
            );
            for (kind, data) in controls(&sent) {
                if kind == UPLOAD_END_KIND {
                    ended = true;
                } else {
                    all.push(serde_json::from_str(&data).unwrap());
                }
            }
        }
        let mut reassembled = Vec::new();
        for chunk in all.iter().filter(|chunk| chunk.file == 0) {
            assert_eq!(chunk.offset, reassembled.len() as u64);
            reassembled.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(&chunk.data)
                    .unwrap(),
            );
        }
        assert_eq!(reassembled, big);
        assert!(all.iter().any(|chunk| chunk.file == 1 && chunk.offset == 0));

        uploads.receive_result(
            &endpoint,
            EndpointUploadResult {
                id: begin.id,
                ok: true,
                paths: vec!["/remote/big.bin".into(), "/remote/small.png".into()],
                pasted: true,
                code: None,
                message: None,
            },
            &mut endpoints,
            now,
        );
        assert!(uploads.is_idle());
        // Large uploads report completion.
        assert!(uploads
            .take_notices()
            .iter()
            .any(|notice| notice.tone == UploadNoticeTone::Done));
    }

    #[test]
    fn a_rejected_upload_reports_and_starts_the_next_drop() {
        let dir = TempDir::new("reject");
        let a = dir.file("a.png", b"a");
        let b = dir.file("b.png", b"b");
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY]);
        let mut uploads = uploads(&[]);
        let now = Instant::now();
        uploads.handle_drop(vec![a], target(), &mut endpoints, now);
        uploads.handle_drop(vec![b], target(), &mut endpoints, now);
        let first: EndpointUploadBegin = serde_json::from_str(&controls(&sent)[0].1).unwrap();
        uploads.receive_result(
            &ClientEndpointId::Local,
            EndpointUploadResult::failure(first.id, "io", "disk full"),
            &mut endpoints,
            now,
        );
        assert_eq!(uploads.take_notices()[0].body, "disk full");
        let next = controls(&sent);
        assert_eq!(next[0].0, UPLOAD_BEGIN_KIND);
        let second: EndpointUploadBegin = serde_json::from_str(&next[0].1).unwrap();
        assert_ne!(second.id, first.id);
    }

    #[test]
    fn losing_the_endpoint_fails_the_active_and_queued_uploads() {
        let dir = TempDir::new("lost");
        let large = dir.file("large.png", &vec![1; 2 * UPLOAD_WINDOW_BYTES as usize]);
        let small = dir.file("small.png", b"a");
        let (mut endpoints, _) = registry(&[UPLOAD_CAPABILITY]);
        let mut uploads = uploads(&[]);
        let now = Instant::now();
        uploads.handle_drop(vec![large], target(), &mut endpoints, now);
        uploads.handle_drop(vec![small], target(), &mut endpoints, now);
        endpoints.disconnect(&ClientEndpointId::Local);
        uploads.tick(&mut endpoints, now);
        assert!(uploads.is_idle());
        let notices = uploads.take_notices();
        assert_eq!(notices.len(), 2);
        assert!(notices
            .iter()
            .all(|notice| notice.tone == UploadNoticeTone::Failed));
    }

    #[test]
    fn a_late_result_after_an_unconfirmed_upload_still_shows_where_it_went() {
        let dir = TempDir::new("late");
        let small = dir.file("small.png", b"a");
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY]);
        let mut uploads = uploads(&[]);
        let now = Instant::now();
        uploads.handle_drop(vec![small], target(), &mut endpoints, now);
        let begin: EndpointUploadBegin = serde_json::from_str(&controls(&sent)[0].1).unwrap();
        uploads.tick(
            &mut endpoints,
            now + UPLOAD_STALL_TIMEOUT + Duration::from_secs(1),
        );
        uploads.take_notices();
        uploads.receive_result(
            &ClientEndpointId::Local,
            EndpointUploadResult {
                id: begin.id,
                ok: true,
                paths: vec!["/remote/small.png".into()],
                pasted: false,
                code: None,
                message: Some("The target pane was no longer visible.".into()),
            },
            &mut endpoints,
            now,
        );
        let notices = uploads.take_notices();
        assert!(notices[0].body.contains("/remote/small.png"));
        assert!(notices[0]
            .body
            .starts_with("The target pane was no longer visible."));
    }

    #[test]
    fn several_images_for_an_old_server_explain_why_they_are_typed() {
        let dir = TempDir::new("old-multi");
        let a = dir.file("a.png", b"a");
        let b = dir.file("b.png", b"b");
        let (mut endpoints, _) = registry(&[]);
        let mut uploads = uploads(&[]);
        assert!(matches!(
            uploads.handle_drop(vec![a, b], target(), &mut endpoints, Instant::now()),
            DropHandling::Ignored
        ));
        assert!(uploads.take_notices()[0]
            .body
            .contains("one image at a time"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_into_a_hidden_directory_is_not_uploaded() {
        let dir = TempDir::new("symlink");
        fs::create_dir_all(dir.0.join(".ssh")).unwrap();
        let secret = dir.file(".ssh/id_ed25519", b"secret");
        let link = dir.0.join("report.pdf");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY, UPLOAD_FILES_CAPABILITY]);
        let mut uploads = uploads(&["pdf"]);
        assert!(matches!(
            uploads.handle_drop(vec![link], target(), &mut endpoints, Instant::now()),
            DropHandling::Ignored
        ));
        assert!(controls(&sent).is_empty());
    }

    #[test]
    fn a_stalled_upload_is_cancelled_unless_every_byte_was_sent() {
        let dir = TempDir::new("stall");
        let large = dir.file("large.png", &vec![1; 2 * UPLOAD_WINDOW_BYTES as usize]);
        let small = dir.file("small.png", b"a");
        let (mut endpoints, sent) = registry(&[UPLOAD_CAPABILITY]);
        let mut uploads = uploads(&[]);
        let now = Instant::now();
        let later = now + UPLOAD_STALL_TIMEOUT + Duration::from_secs(1);

        uploads.handle_drop(vec![large], target(), &mut endpoints, now);
        controls(&sent);
        uploads.tick(&mut endpoints, later);
        assert!(uploads.is_idle());
        assert_eq!(controls(&sent)[0].0, UPLOAD_CANCEL_KIND);
        assert_eq!(uploads.take_notices()[0].tone, UploadNoticeTone::Failed);

        // After `end` the server may still paste, so the client must not cancel.
        uploads.handle_drop(vec![small], target(), &mut endpoints, now);
        assert!(controls(&sent)
            .iter()
            .any(|(kind, _)| kind == UPLOAD_END_KIND));
        uploads.tick(&mut endpoints, later);
        assert!(uploads.is_idle());
        assert!(controls(&sent).is_empty());
        assert!(uploads.take_notices()[0].body.contains("may still appear"));
    }
}
