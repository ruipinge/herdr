//! Stable endpoint compatibility contract for client-owned shells.
//!
//! The endpoint generation is intentionally independent from the private
//! binary protocol used by same-install CLI, direct-terminal, and handoff
//! paths. Generation 1 is the compatibility floor for Local, SSH, and Cloud
//! shell endpoints and must remain available indefinitely unless retired for a
//! security reason. New JSON fields must be optional or have serde defaults;
//! new enum values need an `Unknown` fallback. Unknown named controls are
//! optional and ignored unless negotiated as part of the core.

use serde::{Deserialize, Serialize};

use super::{ClientShellSnapshot, ClientSurfaceSize, ServerMessage};

pub const ENDPOINT_PROTOCOL_GENERATION: u32 = 1;
pub const ENDPOINT_HELLO_KIND: &str = "endpoint.hello.v1";
pub const ENDPOINT_WELCOME_KIND: &str = "endpoint.welcome.v1";
pub const SNAPSHOT_CODEC_V1: &str = "shell.snapshot.v1";
pub const ENDPOINT_SNAPSHOT_KIND: &str = SNAPSHOT_CODEC_V1;
pub const SURFACE_CODEC_V1: &str = "shell.surface.v1";
pub const INPUT_CODEC_V1: &str = "shell.input.semantic.v1";
pub const BLOB_CODEC_V1: &str = "shell.blob.v1";
pub const SURFACE_INTEREST_CAPABILITY: &str = "surface_interest";
pub const PRESENTATION_EFFECTS_FENCE_CAPABILITY: &str = "presentation_effects_fence";
pub const PRESENTATION_EFFECTS_SYNC_KIND: &str = "endpoint.presentation.sync.v1";
pub const PRESENTATION_EFFECTS_READY_KIND: &str = "endpoint.presentation.ready.v1";
pub const HEALTH_CHECK_CAPABILITY: &str = "health_check";
pub const HEALTH_PING_KIND: &str = "endpoint.health.ping.v1";
pub const HEALTH_PONG_KIND: &str = "endpoint.health.pong.v1";
pub const AGENT_VIEW_PROJECTION_CAPABILITY: &str = "agent_view_projection";
pub const AGENT_VIEW_PROJECTION_KIND: &str = "endpoint.agent-view.v1";
pub const AGENT_COMPLETIONS_CAPABILITY: &str = "agent_completions";
pub const AGENT_COMPLETIONS_KIND: &str = "endpoint.agent-completions.v1";
/// The server stages image uploads sent with the `endpoint.upload.*` controls.
pub const UPLOAD_CAPABILITY: &str = "upload";
/// The server owner also accepts uploads of non-image files.
pub const UPLOAD_FILES_CAPABILITY: &str = "upload_files";
pub const UPLOAD_BEGIN_KIND: &str = "endpoint.upload.begin.v1";
pub const UPLOAD_CHUNK_KIND: &str = "endpoint.upload.chunk.v1";
pub const UPLOAD_END_KIND: &str = "endpoint.upload.end.v1";
pub const UPLOAD_CANCEL_KIND: &str = "endpoint.upload.cancel.v1";
pub const UPLOAD_ACK_KIND: &str = "endpoint.upload.ack.v1";
pub const UPLOAD_RESULT_KIND: &str = "endpoint.upload.result.v1";
/// Raw bytes per upload chunk. Base64 keeps each control frame far below `MAX_FRAME_SIZE`,
/// so keystrokes and health checks interleave with a transfer.
pub const UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
/// Most files accepted in one upload batch.
pub const UPLOAD_MAX_FILES: usize = 32;

/// Starts one upload batch. Files are sent in order; their staged paths are pasted
/// together into `target` once every file has arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointUploadBegin {
    pub id: u64,
    pub target: EndpointUploadTarget,
    pub files: Vec<EndpointUploadFile>,
}

/// Where the server pastes the staged paths. Independent of the frozen bincode
/// `ClientClipboardImageTarget` so this JSON codec can grow without touching it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawEndpointUploadTarget", into = "RawEndpointUploadTarget")]
pub enum EndpointUploadTarget {
    Pane(String),
    Popup(String),
    DirectTerminal,
    /// A target kind from a newer client; the server rejects the upload.
    Unknown,
}

/// Wire form `{"kind": "...", "id": "..."}`, decoded leniently so unknown kinds and
/// extra fields become `Unknown` instead of failing the whole control.
#[derive(Serialize, Deserialize)]
struct RawEndpointUploadTarget {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

impl From<RawEndpointUploadTarget> for EndpointUploadTarget {
    fn from(raw: RawEndpointUploadTarget) -> Self {
        match (raw.kind.as_str(), raw.id) {
            ("pane", Some(id)) => Self::Pane(id),
            ("popup", Some(id)) => Self::Popup(id),
            ("direct_terminal", _) => Self::DirectTerminal,
            _ => Self::Unknown,
        }
    }
}

impl From<EndpointUploadTarget> for RawEndpointUploadTarget {
    fn from(target: EndpointUploadTarget) -> Self {
        let (kind, id) = match target {
            EndpointUploadTarget::Pane(id) => ("pane", Some(id)),
            EndpointUploadTarget::Popup(id) => ("popup", Some(id)),
            EndpointUploadTarget::DirectTerminal => ("direct_terminal", None),
            EndpointUploadTarget::Unknown => ("unknown", None),
        };
        Self {
            kind: kind.into(),
            id,
        }
    }
}

impl From<super::ClientClipboardImageTarget> for EndpointUploadTarget {
    fn from(target: super::ClientClipboardImageTarget) -> Self {
        match target {
            super::ClientClipboardImageTarget::Pane(id) => Self::Pane(id),
            super::ClientClipboardImageTarget::Popup(id) => Self::Popup(id),
            super::ClientClipboardImageTarget::DirectTerminal => Self::DirectTerminal,
        }
    }
}

impl EndpointUploadTarget {
    pub fn terminal_target(self) -> Option<super::ClientClipboardImageTarget> {
        match self {
            Self::Pane(id) => Some(super::ClientClipboardImageTarget::Pane(id)),
            Self::Popup(id) => Some(super::ClientClipboardImageTarget::Popup(id)),
            Self::DirectTerminal => Some(super::ClientClipboardImageTarget::DirectTerminal),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointUploadFile {
    /// Original file name without directories. The server sanitizes it.
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointUploadChunk {
    pub id: u64,
    /// Index into `EndpointUploadBegin::files`.
    pub file: u32,
    /// Byte offset of this chunk within the file.
    pub offset: u64,
    /// Standard base64 of at most `UPLOAD_CHUNK_BYTES` raw bytes.
    pub data: String,
}

/// Sent by the client for `UPLOAD_END_KIND` and `UPLOAD_CANCEL_KIND`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointUploadId {
    pub id: u64,
}

/// Flow-control credit: total bytes of the batch the server has written to disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointUploadAck {
    pub id: u64,
    pub received: u64,
}

/// Final outcome of a batch. On success `paths` holds the staged files on the server host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointUploadResult {
    pub id: u64,
    pub ok: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    /// Whether the paths were pasted into the target. False when the target went away.
    #[serde(default)]
    pub pasted: bool,
    /// Machine-readable failure reason. Clients must tolerate unknown codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl EndpointUploadResult {
    pub fn failure(id: u64, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            paths: Vec::new(),
            pasted: false,
            code: Some(code.into()),
            message: Some(message.into()),
        }
    }
}

pub fn upload_control_message<T: Serialize>(
    kind: &str,
    payload: &T,
) -> serde_json::Result<ServerMessage> {
    Ok(ServerMessage::EndpointControl {
        kind: kind.into(),
        data: serde_json::to_string(payload)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAgentCompletions {
    pub boot_id: String,
    pub revision: u64,
    pub completions: std::collections::BTreeMap<String, u64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointClientHello {
    pub generation: u32,
    pub cell_width_px: u32,
    pub cell_height_px: u32,
    pub surface_size: ClientSurfaceSize,
    pub pixel_mouse: bool,
    pub direct_graphics: bool,
    pub endpoint_keybindings: bool,
    pub mouse_capture: bool,
    #[serde(default = "default_true")]
    pub surface_active: bool,
    /// Accept the optional cell-retaining surface encoding on this connection.
    #[serde(default)]
    pub surface_reuse: bool,
    /// Accept the optional surface-delta encoding on this connection.
    #[serde(default)]
    pub surface_delta: bool,
    /// Accept the optional scroll-aware patch encoding on this connection.
    #[serde(default)]
    pub surface_scroll: bool,
    #[serde(default)]
    pub snapshot_codecs: Vec<String>,
    #[serde(default)]
    pub surface_codecs: Vec<String>,
    #[serde(default)]
    pub input_codecs: Vec<String>,
    #[serde(default)]
    pub blob_codecs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointHandshakeError {
    pub code: String,
    pub message: String,
}

/// Optional companion to a V1 snapshot. The view payload is intentionally opaque to this
/// stable envelope so clients can ignore view language additions they do not understand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAgentViewProjection {
    pub boot_id: String,
    pub revision: u64,
    #[serde(default)]
    pub view: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointServerWelcome {
    pub generation: u32,
    pub server_version: String,
    pub snapshot_codec: String,
    pub surface_codec: String,
    pub input_codec: String,
    pub blob_codec: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<EndpointHandshakeError>,
}

pub fn snapshot_message(snapshot: &ClientShellSnapshot) -> serde_json::Result<ServerMessage> {
    Ok(ServerMessage::EndpointControl {
        kind: ENDPOINT_SNAPSHOT_KIND.into(),
        data: serde_json::to_string(snapshot)?,
    })
}

pub fn agent_completions_message(
    projection: &EndpointAgentCompletions,
) -> serde_json::Result<ServerMessage> {
    Ok(ServerMessage::EndpointControl {
        kind: AGENT_COMPLETIONS_KIND.into(),
        data: serde_json::to_string(projection)?,
    })
}

pub fn agent_view_projection_message(
    boot_id: &str,
    revision: u64,
    view: Option<&crate::api::schema::AgentViewSetParams>,
) -> serde_json::Result<ServerMessage> {
    let projection = EndpointAgentViewProjection {
        boot_id: boot_id.to_owned(),
        revision,
        view: view.map(serde_json::to_value).transpose()?,
    };
    Ok(ServerMessage::EndpointControl {
        kind: AGENT_VIEW_PROJECTION_KIND.into(),
        data: serde_json::to_string(&projection)?,
    })
}

impl EndpointClientHello {
    pub fn supports_required_codecs(&self) -> bool {
        self.snapshot_codecs
            .iter()
            .any(|codec| codec == SNAPSHOT_CODEC_V1)
            && self
                .surface_codecs
                .iter()
                .any(|codec| codec == SURFACE_CODEC_V1)
            && self
                .input_codecs
                .iter()
                .any(|codec| codec == INPUT_CODEC_V1)
            && self.blob_codecs.iter().any(|codec| codec == BLOB_CODEC_V1)
    }
}

impl EndpointServerWelcome {
    pub fn compatible(methods: Vec<String>) -> Self {
        Self {
            generation: ENDPOINT_PROTOCOL_GENERATION,
            server_version: crate::build_info::version(),
            snapshot_codec: SNAPSHOT_CODEC_V1.into(),
            surface_codec: SURFACE_CODEC_V1.into(),
            input_codec: INPUT_CODEC_V1.into(),
            blob_codec: BLOB_CODEC_V1.into(),
            methods,
            capabilities: vec![
                super::surface_reuse::CAPABILITY.into(),
                super::surface_delta::CAPABILITY.into(),
                super::surface_scroll::CAPABILITY.into(),
                SURFACE_INTEREST_CAPABILITY.into(),
                PRESENTATION_EFFECTS_FENCE_CAPABILITY.into(),
                HEALTH_CHECK_CAPABILITY.into(),
                AGENT_VIEW_PROJECTION_CAPABILITY.into(),
                AGENT_COMPLETIONS_CAPABILITY.into(),
            ],
            error: None,
        }
    }

    pub fn with_capabilities<'a>(
        mut self,
        capabilities: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        self.capabilities
            .extend(capabilities.into_iter().map(str::to_owned));
        self
    }

    pub fn incompatible(code: &str, message: impl Into<String>) -> Self {
        Self {
            generation: ENDPOINT_PROTOCOL_GENERATION,
            server_version: crate::build_info::version(),
            snapshot_codec: SNAPSHOT_CODEC_V1.into(),
            surface_codec: SURFACE_CODEC_V1.into(),
            input_codec: INPUT_CODEC_V1.into(),
            blob_codec: BLOB_CODEC_V1.into(),
            methods: Vec::new(),
            capabilities: Vec::new(),
            error: Some(EndpointHandshakeError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> EndpointClientHello {
        EndpointClientHello {
            generation: ENDPOINT_PROTOCOL_GENERATION,
            cell_width_px: 8,
            cell_height_px: 16,
            surface_size: ClientSurfaceSize { cols: 80, rows: 24 },
            pixel_mouse: true,
            direct_graphics: false,
            endpoint_keybindings: false,
            mouse_capture: true,
            surface_active: true,
            surface_reuse: false,
            surface_delta: false,
            surface_scroll: false,
            snapshot_codecs: vec![SNAPSHOT_CODEC_V1.into()],
            surface_codecs: vec![SURFACE_CODEC_V1.into()],
            input_codecs: vec![INPUT_CODEC_V1.into()],
            blob_codecs: vec![BLOB_CODEC_V1.into()],
        }
    }

    fn snapshot() -> ClientShellSnapshot {
        ClientShellSnapshot {
            boot_id: "boot".into(),
            revision: 1,
            config_diagnostic: None,
            product_announcement: None,
            update_available: None,
            update_install_command: "herdr update".into(),
            server_keybindings_toml: None,
            latest_release_notes_available: false,
            integration_updates_available: false,
            worktree_directory: String::new(),
            release_notes: None,
            focused_workspace_id: None,
            focused_tab_id: None,
            focused_pane_id: None,
            tab_bar_right: Vec::new(),
            tab_bar_right_separator: String::new(),
            agent_view_label: None,
            agent_order: Vec::new(),
            workspaces: Vec::new(),
            tabs: Vec::new(),
            panes: Vec::new(),
            agents: Vec::new(),
            commands: Vec::new(),
        }
    }

    #[test]
    fn hello_ignores_future_named_fields() {
        let mut value = serde_json::to_value(hello()).unwrap();
        value["future_feature"] = serde_json::json!({"enabled": true});
        let decoded: EndpointClientHello = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, hello());
    }

    #[test]
    fn frozen_generation_one_handshake_decodes() {
        let hello: EndpointClientHello = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/endpoint-hello-v1.json"
        )))
        .unwrap();
        assert!(hello.supports_required_codecs());

        let welcome: EndpointServerWelcome = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/endpoint-welcome-v1.json"
        )))
        .unwrap();
        assert_eq!(welcome.generation, ENDPOINT_PROTOCOL_GENERATION);
        assert_eq!(welcome.snapshot_codec, SNAPSHOT_CODEC_V1);
        assert_eq!(welcome.surface_codec, SURFACE_CODEC_V1);
        assert_eq!(welcome.input_codec, INPUT_CODEC_V1);
        assert_eq!(welcome.blob_codec, BLOB_CODEC_V1);
        assert!(welcome.capabilities.is_empty());
    }

    #[test]
    fn frozen_generation_one_snapshot_decodes() {
        let snapshot: ClientShellSnapshot = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/endpoint-snapshot-v1.json"
        )))
        .unwrap();
        assert_eq!(snapshot.boot_id, "boot-v1");
        assert_eq!(
            snapshot.workspaces[0].agent_status,
            crate::api::schema::AgentStatus::Unknown
        );
    }

    #[test]
    fn snapshot_message_uses_named_json_control() {
        let snapshot = snapshot();
        let ServerMessage::EndpointControl { kind, data } = snapshot_message(&snapshot).unwrap()
        else {
            panic!("snapshot should use endpoint control");
        };
        assert_eq!(kind, ENDPOINT_SNAPSHOT_KIND);
        let decoded: ClientShellSnapshot = serde_json::from_str(&data).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn agent_view_projection_is_an_optional_revision_bound_control() {
        let view = crate::api::schema::AgentViewSetParams {
            source: "example.views".into(),
            label: Some("focus".into()),
            filter: None,
            sort: Vec::new(),
        };
        let ServerMessage::EndpointControl { kind, data } =
            agent_view_projection_message("boot", 7, Some(&view)).unwrap()
        else {
            panic!("projection should use endpoint control");
        };
        assert_eq!(kind, AGENT_VIEW_PROJECTION_KIND);
        let projection: EndpointAgentViewProjection = serde_json::from_str(&data).unwrap();
        assert_eq!(projection.boot_id, "boot");
        assert_eq!(projection.revision, 7);
        assert_eq!(
            projection
                .view
                .map(serde_json::from_value)
                .transpose()
                .unwrap(),
            Some(view)
        );
    }

    #[test]
    fn snapshot_json_tolerates_future_fields_and_command_actions() {
        let mut snapshot = match snapshot_message(&snapshot()).unwrap() {
            ServerMessage::EndpointControl { data, .. } => {
                serde_json::from_str::<serde_json::Value>(&data).unwrap()
            }
            _ => unreachable!(),
        };
        snapshot["future_projection"] = serde_json::json!({"enabled": true});
        snapshot["commands"] = serde_json::json!([{
            "command_id": "future",
            "binding_label": "x",
            "binding_labels": ["x"],
            "action": "FutureAction",
            "description": null
        }]);

        let decoded: ClientShellSnapshot = serde_json::from_value(snapshot).unwrap();
        assert_eq!(
            decoded.commands[0].action,
            crate::protocol::ClientShellCommandAction::Unknown
        );
    }

    #[test]
    fn legacy_hello_defaults_to_an_active_surface() {
        let mut value = serde_json::to_value(hello()).unwrap();
        value.as_object_mut().unwrap().remove("surface_active");
        value.as_object_mut().unwrap().remove("surface_reuse");
        value.as_object_mut().unwrap().remove("surface_delta");
        value.as_object_mut().unwrap().remove("surface_scroll");
        let decoded: EndpointClientHello = serde_json::from_value(value).unwrap();
        assert!(decoded.surface_active);
        assert!(!decoded.surface_reuse);
        assert!(!decoded.surface_delta);
        assert!(!decoded.surface_scroll);
    }

    #[test]
    fn compatible_server_advertises_endpoint_lifecycle_capabilities() {
        let welcome = EndpointServerWelcome::compatible(Vec::new());
        assert_eq!(
            welcome.capabilities,
            vec![
                super::super::surface_reuse::CAPABILITY.to_string(),
                super::super::surface_delta::CAPABILITY.to_string(),
                super::super::surface_scroll::CAPABILITY.to_string(),
                SURFACE_INTEREST_CAPABILITY.to_string(),
                PRESENTATION_EFFECTS_FENCE_CAPABILITY.to_string(),
                HEALTH_CHECK_CAPABILITY.to_string(),
                AGENT_VIEW_PROJECTION_CAPABILITY.to_string(),
                AGENT_COMPLETIONS_CAPABILITY.to_string(),
            ]
        );
    }

    #[test]
    fn required_codecs_are_explicit() {
        let mut value = hello();
        assert!(value.supports_required_codecs());
        value.snapshot_codecs.clear();
        assert!(!value.supports_required_codecs());

        let mut value = hello();
        value.surface_codecs.clear();
        assert!(!value.supports_required_codecs());

        let mut value = hello();
        value.input_codecs.clear();
        assert!(!value.supports_required_codecs());

        let mut value = hello();
        value.blob_codecs.clear();
        assert!(!value.supports_required_codecs());
    }

    #[test]
    fn upload_controls_round_trip_and_tolerate_missing_optional_fields() {
        let begin = EndpointUploadBegin {
            id: 7,
            target: EndpointUploadTarget::Pane("w1:p2".into()),
            files: vec![EndpointUploadFile {
                name: "report.pdf".into(),
                size: 3,
            }],
        };
        let encoded = serde_json::to_string(&begin).unwrap();
        assert_eq!(
            serde_json::from_str::<EndpointUploadBegin>(&encoded).unwrap(),
            begin
        );
        assert!(encoded.contains(r#"{"kind":"pane","id":"w1:p2"}"#));
        let future: EndpointUploadBegin =
            serde_json::from_str(r#"{"id":1,"target":{"kind":"window","id":"x"},"files":[]}"#)
                .unwrap();
        assert_eq!(future.target, EndpointUploadTarget::Unknown);
        let direct: EndpointUploadTarget =
            serde_json::from_str(r#"{"kind":"direct_terminal"}"#).unwrap();
        assert_eq!(direct, EndpointUploadTarget::DirectTerminal);
        let result: EndpointUploadResult =
            serde_json::from_str(r#"{"id":7,"ok":false,"future":1}"#).unwrap();
        assert_eq!(result.code, None);
        assert!(result.paths.is_empty());
        assert!(!result.pasted);
    }

    #[test]
    fn upload_chunks_stay_well_below_the_control_frame_limit() {
        use base64::Engine as _;
        let chunk = EndpointUploadChunk {
            id: u64::MAX,
            file: u32::MAX,
            offset: u64::MAX,
            data: base64::engine::general_purpose::STANDARD.encode(vec![0xff; UPLOAD_CHUNK_BYTES]),
        };
        let message = upload_control_message(UPLOAD_CHUNK_KIND, &chunk).unwrap();
        let mut framed = Vec::new();
        super::super::write_message(&mut framed, &message).unwrap();
        assert!(framed.len() < super::super::MAX_FRAME_SIZE / 4);
    }

    #[test]
    fn welcome_ignores_future_named_fields() {
        let welcome = EndpointServerWelcome::compatible(vec!["pane.close".into()]);
        let mut value = serde_json::to_value(&welcome).unwrap();
        value["future_service"] = serde_json::json!("v2");
        let decoded: EndpointServerWelcome = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, welcome);
    }
}
