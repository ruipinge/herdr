//! Recognize local file paths that a host terminal pastes when files are dropped on it.
//!
//! Terminals paste dropped files as text: one or more absolute paths, shell-escaped or
//! quoted, separated by spaces, often with a trailing space (iTerm2, Alacritty) or
//! newline. A text paste of the same characters is indistinguishable, so callers must
//! still check that each path names an existing regular file before acting on it.

use std::path::PathBuf;

/// Most paths accepted from one drop. Larger lists are forwarded as typed text.
pub(super) const MAX_DROPPED_PATHS: usize = 32;

/// Unix terminal input: an optional bracketed paste around the dropped path list.
#[cfg(unix)]
pub(super) fn dropped_paths_from_terminal_input(data: &[u8]) -> Option<Vec<PathBuf>> {
    let bytes = bracketed_paste_payload(data).unwrap_or(data);
    let text = std::str::from_utf8(bytes).ok()?;
    dropped_paths_from_text(text, PathSyntax::Posix)
}

/// Windows paste text: quoted or bare paths; backslash is a path separator, not an escape.
#[cfg(windows)]
pub(super) fn dropped_paths_from_paste_text(text: &str) -> Option<Vec<PathBuf>> {
    dropped_paths_from_text(text, PathSyntax::Windows)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathSyntax {
    #[cfg_attr(windows, allow(dead_code))] // Windows parses only Windows syntax outside tests.
    Posix,
    #[cfg_attr(unix, allow(dead_code))] // Unix parses only POSIX syntax outside tests.
    Windows,
}

fn dropped_paths_from_text(text: &str, syntax: PathSyntax) -> Option<Vec<PathBuf>> {
    let text = text.trim_end_matches(['\r', '\n']);
    if text.contains(['\r', '\n']) {
        return None;
    }
    let tokens = tokenize(text, syntax)
        .filter(|tokens| !tokens.is_empty() && tokens.len() <= MAX_DROPPED_PATHS)
        .map(|tokens| tokens.into_iter().map(PathBuf::from).collect::<Vec<_>>())
        .filter(|paths| paths.iter().all(|path| is_local_absolute(path)));
    if let Some(paths) = &tokens {
        if paths.len() == 1 || paths.iter().all(|path| path.exists()) {
            return tokens;
        }
    }
    // Some terminals paste one dropped path verbatim, without escaping its spaces.
    whole_text_path(text).or(tokens)
}

fn whole_text_path(text: &str) -> Option<Vec<PathBuf>> {
    let text = text.trim_end_matches([' ', '\t']);
    let text = strip_matching_quotes(text);
    let path = PathBuf::from(text);
    (is_local_absolute(&path) && path.exists()).then(|| vec![path])
}

/// Absolute and not a network or device path. Probing `\\host\share` on Windows makes
/// an SMB connection that can leak credentials, so such text is never touched.
fn is_local_absolute(path: &std::path::Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    // Two leading separators in any mix (`\\`, `//`, `/\`) name a network share.
    let text = path.to_string_lossy();
    let mut chars = text.chars();
    let separator = |ch: Option<char>| matches!(ch, Some('/' | '\\'));
    if separator(chars.next()) && separator(chars.next()) {
        return false;
    }
    is_local_drive_path(path)
}

/// Windows: only drive paths (`C:\...`, `\\?\C:\...`); UNC, device and other verbatim
/// prefixes are refused.
#[cfg(windows)]
fn is_local_drive_path(path: &std::path::Path) -> bool {
    use std::path::{Component, Prefix};

    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

#[cfg(not(windows))]
fn is_local_drive_path(_path: &std::path::Path) -> bool {
    true
}

fn strip_matching_quotes(text: &str) -> &str {
    for quote in ['\'', '"'] {
        if let Some(inner) = text
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    text
}

/// Split on unquoted, unescaped spaces and tabs. Unterminated quotes or a dangling
/// escape reject the whole input so ordinary typed text is never reinterpreted.
fn tokenize(text: &str, syntax: PathSyntax) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            '\\' if syntax == PathSyntax::Posix => {
                current.push(chars.next()?);
                in_token = true;
            }
            '\'' if syntax == PathSyntax::Posix => {
                loop {
                    match chars.next()? {
                        '\'' => break,
                        quoted => current.push(quoted),
                    }
                }
                in_token = true;
            }
            '"' => {
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' if syntax == PathSyntax::Posix => current.push(chars.next()?),
                        quoted => current.push(quoted),
                    }
                }
                in_token = true;
            }
            other => {
                current.push(other);
                in_token = true;
            }
        }
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

#[cfg(unix)]
fn bracketed_paste_payload(data: &[u8]) -> Option<&[u8]> {
    const START: &[u8] = b"\x1b[200~";
    const END: &[u8] = b"\x1b[201~";
    data.strip_prefix(START)?.strip_suffix(END)
}

#[cfg(test)]
mod tests {
    use super::*;

    // POSIX test paths such as `/tmp/a.png` are not absolute on Windows.
    #[cfg(unix)]
    fn posix(text: &str) -> Option<Vec<String>> {
        dropped_paths_from_text(text, PathSyntax::Posix).map(|paths| {
            paths
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect()
        })
    }

    #[cfg(unix)]
    #[test]
    fn single_paths_accept_escapes_quotes_and_line_endings() {
        assert_eq!(posix("/tmp/a.png"), Some(vec!["/tmp/a.png".into()]));
        assert_eq!(posix("/tmp/a\\ b.pdf\n"), Some(vec!["/tmp/a b.pdf".into()]));
        assert_eq!(posix("'/tmp/a b.pdf'"), Some(vec!["/tmp/a b.pdf".into()]));
        assert_eq!(
            posix("\"/tmp/a \\\"b\\\".pdf\""),
            Some(vec!["/tmp/a \"b\".pdf".into()])
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_trailing_space_after_the_path_is_a_separator_not_part_of_it() {
        // iTerm2 and Alacritty append one space after dropped paths (#4500).
        assert_eq!(
            posix("/private/tmp/drop-test.png "),
            Some(vec!["/private/tmp/drop-test.png".into()])
        );
        assert_eq!(posix("/tmp/a\\ "), Some(vec!["/tmp/a ".into()]));
    }

    #[cfg(unix)]
    #[test]
    fn multiple_dropped_paths_are_split_in_order() {
        assert_eq!(
            posix("/Users/me/Shot\\ 1.png /Users/me/Shot\\ 2.png "),
            Some(vec![
                "/Users/me/Shot 1.png".into(),
                "/Users/me/Shot 2.png".into()
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn macos_screenshot_narrow_no_break_space_stays_inside_the_name() {
        let name = "/Users/me/Screenshot 2026-07-08 at 12.14.03\u{202f}PM.png";
        let escaped = name.replace(' ', "\\ ");
        assert_eq!(posix(&escaped), Some(vec![name.into()]));
    }

    #[cfg(unix)]
    #[test]
    fn typed_text_is_not_reinterpreted_as_paths() {
        assert_eq!(posix(""), None);
        assert_eq!(posix("   "), None);
        assert_eq!(posix("relative.png"), None);
        assert_eq!(posix("/tmp/a.png relative.png"), None);
        assert_eq!(posix("/tmp/a.png\n/tmp/b.png"), None);
        assert_eq!(posix("'/tmp/unterminated"), None);
        assert_eq!(posix("/tmp/dangling\\"), None);
        let too_many = vec!["/tmp/x"; MAX_DROPPED_PATHS + 1].join(" ");
        assert_eq!(posix(&too_many), None);
    }

    #[test]
    fn network_and_device_paths_are_never_probed() {
        assert!(!is_local_absolute(std::path::Path::new(
            "//host/share/a.pdf"
        )));
        assert!(!is_local_absolute(std::path::Path::new(
            "\\\\host\\share\\a.pdf"
        )));
        assert!(!is_local_absolute(std::path::Path::new("\\\\?\\C:\\a.pdf")));
        assert!(!is_local_absolute(std::path::Path::new(
            "/\\host\\share\\a.pdf"
        )));
        assert!(!is_local_absolute(std::path::Path::new(
            "\\/host/share/a.pdf"
        )));
    }

    #[cfg(windows)]
    #[test]
    fn windows_paste_text_accepts_quoted_drive_paths_and_rejects_unc() {
        assert_eq!(
            dropped_paths_from_paste_text("\"C:\\My Docs\\a.pdf\" C:\\b.png"),
            Some(vec![
                PathBuf::from("C:\\My Docs\\a.pdf"),
                PathBuf::from("C:\\b.png")
            ])
        );
        assert_eq!(
            dropped_paths_from_paste_text("\\\\host\\share\\a.pdf"),
            None
        );
        assert_eq!(dropped_paths_from_paste_text("\\\\.\\pipe\\x.pdf"), None);
        assert_eq!(
            dropped_paths_from_paste_text("\\\\?\\UNC\\host\\s\\a.pdf"),
            None
        );
        assert_eq!(dropped_paths_from_paste_text("relative.pdf"), None);
    }

    #[test]
    fn windows_paths_keep_backslashes_and_group_quotes() {
        let tokens = tokenize(
            "\"C:\\Users\\me\\My Docs\\a.pdf\" C:\\b.png",
            PathSyntax::Windows,
        )
        .unwrap();
        assert_eq!(tokens, ["C:\\Users\\me\\My Docs\\a.pdf", "C:\\b.png"]);
    }

    #[cfg(unix)]
    #[test]
    fn an_unescaped_single_path_with_spaces_falls_back_to_the_whole_text() {
        let dir = std::env::temp_dir().join(format!(
            "herdr-drop-paths-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("My Shot.png");
        std::fs::write(&file, b"png").unwrap();
        let text = file.to_string_lossy().into_owned();
        let expected = Some(vec![text.clone()]);
        assert_eq!(posix(&text), expected);
        assert_eq!(posix(&format!("{text} ")), expected);
        assert_eq!(posix(&format!("'{text}'")), expected);
        assert_eq!(posix(&format!("{text}\n")), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bracketed_paste_wrappers_are_removed() {
        let paths = dropped_paths_from_terminal_input(b"\x1b[200~/tmp/a.png \x1b[201~").unwrap();
        assert_eq!(paths, vec![PathBuf::from("/tmp/a.png")]);
    }
}
