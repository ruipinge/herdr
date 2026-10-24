use tracing::{info, warn};

#[cfg(windows)]
use crate::protocol::ClientInputEvent;
use crate::protocol::MAX_CLIPBOARD_IMAGE_PAYLOAD;
use crate::protocol::{ClientClipboardImageTarget, ClientMessage};

use super::{write_to_server, ClientError};

pub(super) fn write_remote_image_to_server(
    stream: &mut impl super::ClientMessageSink,
    target: ClientClipboardImageTarget,
    image: crate::platform::ClipboardImage,
    source: &'static str,
) -> Result<(), ClientError> {
    if image.bytes.len() > MAX_CLIPBOARD_IMAGE_PAYLOAD {
        warn!(
            bytes = image.bytes.len(),
            max = MAX_CLIPBOARD_IMAGE_PAYLOAD,
            source,
            "local image is too large to bridge"
        );
        return Ok(());
    }

    info!(
        bytes = image.bytes.len(),
        extension = image.extension,
        source,
        "bridging local image to remote server"
    );
    write_to_server(
        stream,
        &ClientMessage::ClipboardImage {
            target,
            extension: image.extension.to_owned(),
            data: image.bytes,
        },
    )
    .map_err(ClientError::ConnectionLost)
}

pub(super) fn client_remote_image_paste_key(
    config: &crate::config::Config,
) -> Option<(crossterm::event::KeyCode, crossterm::event::KeyModifiers)> {
    match config.remote_image_paste_key() {
        Ok(key) => key,
        Err(diagnostic) => {
            warn!(diagnostic = %diagnostic, "local remote image paste key config diagnostic");
            None
        }
    }
}

pub(super) fn endpoint_accepts_local_images(
    remote_client_process: bool,
    endpoint_id: &super::endpoint::ClientEndpointId,
    active_surface_available: bool,
) -> bool {
    active_surface_available && (remote_client_process || !endpoint_id.is_local())
}

#[cfg(unix)]
pub(super) fn should_bridge_clipboard_image_paste(
    data: &[u8],
    is_remote_client: bool,
    remote_image_paste_key: Option<(crossterm::event::KeyCode, crossterm::event::KeyModifiers)>,
) -> bool {
    if !is_remote_client {
        return false;
    }
    if data == b"\x1b[200~\x1b[201~" {
        return true;
    }

    let Some(remote_image_paste_key) = remote_image_paste_key else {
        return false;
    };

    let events = crate::raw_input::parse_framed_input(data);
    matches!(
        events.as_slice(),
        [crate::raw_input::RawInputEvent::Key(key)]
            if key.kind == crossterm::event::KeyEventKind::Press
                && crate::config::terminal_key_matches_combo(key, remote_image_paste_key)
    )
}

#[cfg(windows)]
pub(super) fn should_bridge_clipboard_image_events(
    events: &[ClientInputEvent],
    is_remote_client: bool,
    remote_image_paste_key: Option<(crossterm::event::KeyCode, crossterm::event::KeyModifiers)>,
) -> bool {
    if !is_remote_client {
        return false;
    }
    if matches!(events, [ClientInputEvent::Paste { text }] if text.is_empty()) {
        return true;
    }

    let Some(remote_image_paste_key) = remote_image_paste_key else {
        return false;
    };
    matches!(
        events,
        [event]
            if matches!(
                event.to_raw_input_event(),
                crate::raw_input::RawInputEvent::Key(key)
                    if key.kind == crossterm::event::KeyEventKind::Press
                        && crate::config::terminal_key_matches_combo(
                            &key,
                            remote_image_paste_key,
                        )
            )
    )
}
