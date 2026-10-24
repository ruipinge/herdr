use std::path::{Component, Path, PathBuf};

use super::Config;

/// Extensions bridged as images without any upload configuration.
const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp"];

pub(crate) fn is_image_extension(extension: &str) -> bool {
    IMAGE_EXTENSIONS
        .iter()
        .any(|image| image.eq_ignore_ascii_case(extension))
}

pub(crate) fn is_image_file_name(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(is_image_extension)
}

/// Which dropped local files a client uploads to remote servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientUploadPolicy {
    extensions: Vec<String>,
    any_file: bool,
    pub(crate) max_bytes: u64,
}

impl Default for ClientUploadPolicy {
    fn default() -> Self {
        Self {
            extensions: Vec::new(),
            any_file: false,
            max_bytes: super::DEFAULT_CLIENT_UPLOAD_MAX_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientUploadDecision {
    Image,
    File,
    /// Not eligible; the drop is forwarded as typed text.
    Skip,
}

impl ClientUploadPolicy {
    /// Classify one local path. Non-image files must match the allow list and must not
    /// look like a secret: hidden names and anything below a hidden directory (for
    /// example `~/.ssh`) are never uploaded, because a pasted path is indistinguishable
    /// from a dropped file.
    pub(crate) fn decide(&self, path: &Path) -> ClientUploadDecision {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if extension.is_some_and(is_image_extension) {
            return ClientUploadDecision::Image;
        }
        if has_hidden_component(path) {
            return ClientUploadDecision::Skip;
        }
        let allowed = self.any_file
            || extension.is_some_and(|extension| {
                self.extensions
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(extension))
            });
        if allowed {
            ClientUploadDecision::File
        } else {
            ClientUploadDecision::Skip
        }
    }
}

fn has_hidden_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => name.to_str().is_none_or(|name| name.starts_with('.')),
        _ => false,
    })
}

/// How a server stages uploads from its clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerUploadPolicy {
    pub(crate) accept_files: bool,
    pub(crate) max_bytes: u64,
    pub(crate) retention: std::time::Duration,
    pub(crate) dir: PathBuf,
}

impl Config {
    pub(crate) fn client_upload_policy(&self) -> ClientUploadPolicy {
        let mut policy = ClientUploadPolicy {
            max_bytes: self.remote.upload_max_bytes,
            ..ClientUploadPolicy::default()
        };
        for entry in &self.remote.upload_extensions {
            let entry = entry.trim();
            if entry == "*" {
                policy.any_file = true;
            } else if valid_extension(entry) {
                policy.extensions.push(entry.to_ascii_lowercase());
            }
        }
        policy
    }

    pub(crate) fn server_upload_policy(&self) -> ServerUploadPolicy {
        let server = &self.server;
        let dir = server
            .upload_dir
            .as_deref()
            .map(str::trim)
            .filter(|dir| !dir.is_empty())
            .map(crate::worktree::expand_tilde_absolute_path)
            .unwrap_or_else(|| super::cache_dir().join("uploads"));
        ServerUploadPolicy {
            accept_files: server.accept_uploads,
            max_bytes: server.upload_max_bytes,
            retention: std::time::Duration::from_secs(
                server.upload_retention_hours.max(1).saturating_mul(60 * 60),
            ),
            dir,
        }
    }

    pub(crate) fn upload_diagnostics(&self) -> Vec<String> {
        let mut diagnostics = self
            .remote
            .upload_extensions
            .iter()
            .filter(|entry| {
                let entry = entry.trim();
                entry != "*" && !valid_extension(entry)
            })
            .map(|entry| {
                format!(
                    "remote.upload_extensions entry {entry:?} must be an extension without a dot, or \"*\"; ignoring it"
                )
            })
            .collect::<Vec<_>>();
        if self.server.upload_retention_hours == 0 {
            diagnostics
                .push("server.upload_retention_hours must be at least 1; using 1".to_owned());
        }
        diagnostics
    }
}

fn valid_extension(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= 16
        && entry
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(extensions: &[&str]) -> ClientUploadPolicy {
        let mut config = Config::default();
        config.remote.upload_extensions = extensions.iter().map(|entry| (*entry).into()).collect();
        config.client_upload_policy()
    }

    #[test]
    fn images_upload_without_configuration() {
        let policy = ClientUploadPolicy::default();
        assert_eq!(
            policy.decide(Path::new("/tmp/a.PNG")),
            ClientUploadDecision::Image
        );
        assert_eq!(
            policy.decide(Path::new("/tmp/a.pdf")),
            ClientUploadDecision::Skip
        );
    }

    #[test]
    fn allow_list_matches_extensions_case_insensitively() {
        let policy = policy(&["PDF", " csv "]);
        assert_eq!(
            policy.decide(Path::new("/tmp/a.pdf")),
            ClientUploadDecision::File
        );
        assert_eq!(
            policy.decide(Path::new("/tmp/a.CSV")),
            ClientUploadDecision::File
        );
        assert_eq!(
            policy.decide(Path::new("/tmp/a.zip")),
            ClientUploadDecision::Skip
        );
        assert_eq!(
            policy.decide(Path::new("/tmp/Makefile")),
            ClientUploadDecision::Skip
        );
    }

    #[test]
    fn wildcard_allows_files_without_extensions() {
        let policy = policy(&["*"]);
        assert_eq!(
            policy.decide(Path::new("/tmp/Makefile")),
            ClientUploadDecision::File
        );
    }

    #[test]
    fn hidden_names_and_hidden_directories_are_never_uploaded() {
        let policy = policy(&["*"]);
        assert_eq!(
            policy.decide(Path::new("/home/me/.ssh/id_ed25519")),
            ClientUploadDecision::Skip
        );
        assert_eq!(
            policy.decide(Path::new("/home/me/.aws/credentials.csv")),
            ClientUploadDecision::Skip
        );
        assert_eq!(
            policy.decide(Path::new("/home/me/.env")),
            ClientUploadDecision::Skip
        );
        // Images keep their existing behavior wherever they live.
        assert_eq!(
            policy.decide(Path::new("/home/me/.cache/shot.png")),
            ClientUploadDecision::Image
        );
    }

    #[test]
    fn invalid_extension_entries_are_reported_and_ignored() {
        let mut config = Config::default();
        config.remote.upload_extensions = vec![".pdf".into(), "txt".into(), "a/b".into()];
        let policy = config.client_upload_policy();
        assert_eq!(
            policy.decide(Path::new("/tmp/a.txt")),
            ClientUploadDecision::File
        );
        assert_eq!(
            policy.decide(Path::new("/tmp/a.pdf")),
            ClientUploadDecision::Skip
        );
        assert_eq!(config.upload_diagnostics().len(), 2);
    }

    #[test]
    fn server_defaults_reject_files_and_stage_in_the_cache_dir() {
        let policy = Config::default().server_upload_policy();
        assert!(!policy.accept_files);
        assert!(policy.dir.ends_with("uploads"));
        assert_eq!(
            policy.retention,
            std::time::Duration::from_secs(24 * 60 * 60)
        );
    }
}
