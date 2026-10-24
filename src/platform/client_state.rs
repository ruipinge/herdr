use std::path::Path;

#[cfg(not(windows))]
pub(crate) fn create_private_state_file(path: &Path) -> std::io::Result<std::fs::File> {
    super::create_remote_ssh_config_file(path)
}

#[cfg(windows)]
pub(crate) fn create_private_state_file(path: &Path) -> std::io::Result<std::fs::File> {
    super::windows::create_remote_ssh_config_file(path)
}

/// Create one directory that only the current user can access.
#[cfg(not(windows))]
pub(crate) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    super::create_remote_private_dir(path)
}

#[cfg(windows)]
pub(crate) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    super::windows::create_remote_private_dir(path)
}

/// Whether existing file metadata belongs to the current user.
#[cfg(unix)]
pub(crate) fn owned_by_current_user(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and cannot fail.
    metadata.uid() == unsafe { libc::geteuid() }
}

/// Windows directories created here carry an owner-only ACL; ownership is not checked.
#[cfg(not(unix))]
pub(crate) fn owned_by_current_user(_metadata: &std::fs::Metadata) -> bool {
    true
}

#[cfg(not(windows))]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    super::windows::replace_file(source, destination)
}

#[cfg(not(windows))]
pub(crate) fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
pub(crate) fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    // replace_file uses MOVEFILE_WRITE_THROUGH on Windows.
    Ok(())
}
