//! Rewrites applied to the keystrokes `dev shell` forwards into a container.
//!
//! Two of them today: Shift+Enter becomes a plain carriage return, and a
//! bracketed paste naming a file on this host is carried into the
//! container so the pasted path resolves there (see [`PasteFilter`]).

use std::ops::Range;
use std::path::{Path, PathBuf};

/// Translate Shift+Enter escape sequences into a plain carriage return.
///
/// Terminals encode Shift+Enter in several ways:
///   - CSI u (kitty/VS Code):  ESC [ 1 3 ; 2 u   (\x1b[13;2u)
///   - xterm modifyOtherKeys:  ESC [ 2 7 ; 2 ; 1 3 ~  (\x1b[27;2;13~)
///
/// Shells inside containers often don't understand these, causing garbled
/// output. We rewrite them to a plain \r which the shell treats as Enter.
pub fn translate_shift_enter(input: &[u8]) -> Vec<u8> {
    const CSI_U: &[u8] = b"\x1b[13;2u";
    const XTERM: &[u8] = b"\x1b[27;2;13~";

    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == 0x1b {
            if input[i..].starts_with(CSI_U) {
                out.push(b'\r');
                i += CSI_U.len();
                continue;
            }
            if input[i..].starts_with(XTERM) {
                out.push(b'\r');
                i += XTERM.len();
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

/// A paste that never closes is forwarded as-is once it grows past this, so a
/// terminal that lost the end marker cannot wedge the session.
const MAX_HELD_PASTE: usize = 1 << 20;

/// Where pasted files land in the container.
pub const CONTAINER_PASTE_DIR: &str = "/tmp/dev-paste";

/// `paste_bridge::copy_in` reads the whole file into memory, so this is
/// what bounds that read.
const MAX_PASTED_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// One run of input, split at bracketed-paste boundaries.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// Ordinary keystrokes, forwarded after the usual key translation.
    Keys(Vec<u8>),
    /// The body of one bracketed paste, markers stripped.
    Paste(Vec<u8>),
}

/// Splits a byte stream into keystrokes and bracketed pastes.
///
/// Terminals send a paste as `ESC[200~ … ESC[201~` when the application asked
/// for bracketed paste mode, which Claude Code does, and that is the only
/// framing in which it treats a pasted path as an image to attach. Reads
/// arrive in fixed-size chunks, so a marker or a paste body can straddle two
/// calls to [`PasteFilter::feed`]; bytes that might be the start of a marker
/// are held until the next chunk settles it.
#[derive(Default)]
pub struct PasteFilter {
    held: Vec<u8>,
    in_paste: bool,
    /// How many leading bytes of `held` a prior call already confirmed hold no
    /// `PASTE_END`, while `in_paste`. Lets `take_paste` resume scanning near the
    /// chunk boundary instead of rescanning the whole held paste from the start.
    paste_scanned: usize,
}

impl PasteFilter {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Input> {
        self.held.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let progressed = if self.in_paste {
                self.take_paste(&mut out)
            } else {
                self.take_keys(&mut out)
            };
            if !progressed {
                break;
            }
        }
        out
    }

    /// Emit keystrokes up to the next paste start. Returns false once nothing
    /// more can be decided without further input.
    fn take_keys(&mut self, out: &mut Vec<Input>) -> bool {
        if let Some(at) = find(&self.held, PASTE_START) {
            let keys = self
                .held
                .drain(..at + PASTE_START.len())
                .collect::<Vec<u8>>();
            push_keys(out, keys[..at].to_vec());
            self.in_paste = true;
            self.paste_scanned = 0;
            return true;
        }
        let keep = marker_prefix_len(&self.held, PASTE_START);
        let keys = self
            .held
            .drain(..self.held.len() - keep)
            .collect::<Vec<u8>>();
        push_keys(out, keys);
        false
    }

    /// Emit the paste body once its end marker has arrived.
    ///
    /// Scans only from `paste_scanned`, minus the marker's length so a match
    /// straddling this call's chunk boundary is still found, rather than
    /// rescanning bytes already confirmed clean by an earlier call: with the
    /// whole held paste rescanned from zero on every chunk, one large paste
    /// costs time quadratic in its size.
    fn take_paste(&mut self, out: &mut Vec<Input>) -> bool {
        let resume_from = self.paste_scanned.saturating_sub(PASTE_END.len() - 1);
        if let Some(rel) = find(&self.held[resume_from..], PASTE_END) {
            let at = resume_from + rel;
            let body = self.held.drain(..at + PASTE_END.len()).collect::<Vec<u8>>();
            out.push(Input::Paste(body[..at].to_vec()));
            self.in_paste = false;
            self.paste_scanned = 0;
            return true;
        }
        self.paste_scanned = self.held.len();
        if self.held.len() > MAX_HELD_PASTE {
            let mut raw = PASTE_START.to_vec();
            raw.append(&mut self.held);
            push_keys(out, raw);
            self.in_paste = false;
            self.paste_scanned = 0;
        }
        false
    }

    /// Whether `held` is currently an incomplete prefix of the paste-start
    /// marker, rather than genuine in-progress paste body bytes.
    ///
    /// The filter itself cannot tell whether more bytes are coming — that
    /// timing decision belongs to whoever is feeding it — so this only
    /// answers "is what's held safe to release without more input", which is
    /// true exactly when `take_keys` stopped short of a full marker. A held
    /// paste body must never be reported this way: a real paste can have long
    /// gaps between chunks and must not be torn in half by an impatient
    /// caller.
    pub fn holding_marker_prefix(&self) -> bool {
        !self.in_paste && !self.held.is_empty()
    }

    /// Release the held marker-prefix bytes as ordinary keystrokes.
    pub fn take_held_prefix(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

fn push_keys(out: &mut Vec<Input>, keys: Vec<u8>) {
    if !keys.is_empty() {
        out.push(Input::Keys(keys));
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Length of the longest tail of `bytes` that is a proper prefix of `marker`.
fn marker_prefix_len(bytes: &[u8], marker: &[u8]) -> usize {
    (1..marker.len())
        .rev()
        .find(|&n| bytes.len() >= n && bytes[bytes.len() - n..] == marker[..n])
        .unwrap_or(0)
}

/// A shell word in a paste that names a file this host can bridge into the
/// container.
#[derive(Debug, PartialEq, Eq)]
pub struct PastedFile {
    /// Byte range of the word in the paste body.
    pub span: Range<usize>,
    pub host_path: PathBuf,
}

/// The files a paste names, in order of appearance — or none, unless every
/// word in the paste qualifies.
///
/// A word qualifies when it is an absolute path, resolves (via
/// [`std::fs::canonicalize`]) to a regular file no larger than
/// [`MAX_PASTED_FILE_BYTES`], and that canonical path sits under one of the
/// [`paste_roots`]. The last guard exists so a pasted system path such as
/// `/etc/hosts` is never silently swapped for a copy of this host's own
/// file. A Mac path pasted into a `dev shell` on an ssh box resolves
/// nowhere there and passes through untouched.
///
/// The all-or-nothing rule keeps drag-and-drop of one or several files
/// working while refusing to touch a paste that mixes a path in with
/// anything else, such as `scp /Users/me/.ssh/id_ed25519 box:` — bridging
/// only the path there would copy a private key into the container and
/// rewrite the command to run against the copy.
pub fn pasted_files(paste: &[u8]) -> Vec<PastedFile> {
    let Ok(text) = std::str::from_utf8(paste) else {
        return Vec::new();
    };
    let words = shell_words(text);
    if words.is_empty() {
        return Vec::new();
    }
    let mut files = Vec::with_capacity(words.len());
    for word in words {
        if !word.text.starts_with('/') {
            return Vec::new();
        }
        let host_path = PathBuf::from(word.text);
        if !is_pasteable_file(&host_path) {
            return Vec::new();
        }
        files.push(PastedFile {
            span: word.span,
            host_path,
        });
    }
    files
}

/// Canonicalising must run first, so the guard sees the same resolved path a
/// symlink would otherwise let slip past `under_a_paste_root`; the root check
/// runs before `metadata` so a path outside every root costs no extra syscall.
fn is_pasteable_file(path: &Path) -> bool {
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    if !under_a_paste_root(&canonical) {
        return false;
    }
    std::fs::metadata(&canonical).is_ok_and(|m| m.is_file() && m.len() <= MAX_PASTED_FILE_BYTES)
}

fn under_a_paste_root(canonical: &Path) -> bool {
    paste_roots().iter().any(|root| canonical.starts_with(root))
}

/// Directories a pasted path's canonical form must sit under to be bridged:
/// `$HOME`, `$TMPDIR`, and `/tmp`, each canonicalised so a symlinked root
/// (as `/tmp` and `$TMPDIR` are on macOS) still matches. A root that fails
/// to resolve is dropped rather than widening the guard.
///
/// Resolved once and cached: none of these can change during a session, and a
/// paste can name many candidate paths in one go.
fn paste_roots() -> &'static [PathBuf] {
    static ROOTS: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        [
            dirs::home_dir(),
            Some(std::env::temp_dir()),
            Some(PathBuf::from("/tmp")),
        ]
        .into_iter()
        .flatten()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect()
    })
}

/// The container path a pasted host file is copied to.
///
/// The name is reduced to a shell-safe subset so the pasted path never needs
/// escaping, and a paste is otherwise left byte-for-byte as it arrived. A
/// digest of the full host path is prefixed so two files that share a
/// basename but live in different directories — `~/a/shot.png` and
/// `~/b/shot.png` — land at distinct container paths instead of the second
/// silently overwriting the first.
pub fn container_paste_path(host_path: &Path) -> String {
    let name = host_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("image");
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "{CONTAINER_PASTE_DIR}/{}-{safe}",
        host_path_digest(host_path)
    )
}

/// A short, stable digest of a pasted file's full host path.
///
/// Hashing the full path rather than resolving it also keeps this stable
/// across pastes of the same path: the same host path always yields the same
/// container name, so re-pasting it overwrites the earlier copy instead of
/// accumulating a fresh one.
fn host_path_digest(host_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(host_path.to_string_lossy().as_bytes());
    hex::encode(&hasher.finalize()[..4])
}

/// The paste with the given words swapped for replacements, markers restored.
/// `replacements` must be in ascending, non-overlapping span order.
pub fn rewrite_paste(paste: &[u8], replacements: &[(Range<usize>, String)]) -> Vec<u8> {
    let mut out = PASTE_START.to_vec();
    let mut cursor = 0;
    for (span, text) in replacements {
        out.extend_from_slice(&paste[cursor..span.start]);
        out.extend_from_slice(text.as_bytes());
        cursor = span.end;
    }
    out.extend_from_slice(&paste[cursor..]);
    out.extend_from_slice(PASTE_END);
    out
}

struct ShellWord {
    span: Range<usize>,
    text: String,
}

/// Split `text` the way a POSIX shell would, keeping each word's byte span.
///
/// Handles the escaping a terminal applies when it pastes a path: backslash
/// before a special character, single quotes around a name with newlines, and
/// double quotes. Whitespace outside quotes separates words.
///
/// Only ASCII whitespace separates, matching the shell's default `IFS`. Every
/// other Unicode space is an ordinary filename character, and macOS puts one
/// (U+202F, before the AM/PM) in every screenshot it saves; a terminal escapes
/// the ASCII spaces in that name and leaves the narrow one bare, so splitting
/// on `char::is_whitespace` tore the path in two and the bridge skipped it.
fn shell_words(text: &str) -> Vec<ShellWord> {
    let mut words = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
            continue;
        }
        let mut word = String::new();
        let mut end = start;
        let mut quote: Option<char> = None;
        while let Some(&(i, c)) = chars.peek() {
            match quote {
                Some('\'') if c == '\'' => quote = None,
                Some('\'') => word.push(c),
                Some(_) if c == '"' => quote = None,
                Some(_) if c == '\\' => {
                    chars.next();
                    let Some(&(j, escaped)) = chars.peek() else {
                        break;
                    };
                    word.push(escaped);
                    // `end` must land after the escaped character, not the
                    // backslash: the generic update below only advances past
                    // whatever `chars.peek()` last returned, which by now is
                    // the escaped character, so it is set here instead.
                    chars.next();
                    end = j + escaped.len_utf8();
                    continue;
                }
                Some(_) => word.push(c),
                None if c.is_ascii_whitespace() => break,
                None if c == '\'' || c == '"' => quote = Some(c),
                None if c == '\\' => {
                    chars.next();
                    let Some(&(j, escaped)) = chars.peek() else {
                        break;
                    };
                    word.push(escaped);
                    chars.next();
                    end = j + escaped.len_utf8();
                    continue;
                }
                None => word.push(c),
            }
            chars.next();
            end = i + c.len_utf8();
        }
        words.push(ShellWord {
            span: start..end,
            text: word,
        });
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn keys(s: &[u8]) -> Input {
        Input::Keys(s.to_vec())
    }

    fn paste(s: &[u8]) -> Input {
        Input::Paste(s.to_vec())
    }

    #[test]
    fn keystrokes_pass_through_unchanged() {
        let mut f = PasteFilter::default();
        assert_eq!(f.feed(b"ls -la\r"), vec![keys(b"ls -la\r")]);
    }

    #[test]
    fn a_whole_paste_in_one_chunk_is_split_out() {
        let mut f = PasteFilter::default();
        let got = f.feed(b"ab\x1b[200~/x.png\x1b[201~cd");
        assert_eq!(got, vec![keys(b"ab"), paste(b"/x.png"), keys(b"cd")]);
    }

    #[test]
    fn a_paste_split_across_chunks_is_reassembled() {
        let mut f = PasteFilter::default();
        assert_eq!(f.feed(b"\x1b[200~/Users/me/sh"), vec![]);
        assert_eq!(f.feed(b"ot.png\x1b[20"), vec![]);
        assert_eq!(
            f.feed(b"1~\r"),
            vec![paste(b"/Users/me/shot.png"), keys(b"\r")]
        );
    }

    #[test]
    fn a_start_marker_split_across_chunks_is_not_leaked_as_keys() {
        let mut f = PasteFilter::default();
        assert_eq!(f.feed(b"x\x1b[2"), vec![keys(b"x")]);
        assert_eq!(f.feed(b"00~p\x1b[201~"), vec![paste(b"p")]);
    }

    #[test]
    fn a_lone_escape_is_released_once_it_is_not_a_marker() {
        let mut f = PasteFilter::default();
        assert_eq!(f.feed(b"\x1b"), vec![]);
        assert_eq!(f.feed(b"[A"), vec![keys(b"\x1b[A")]);
    }

    #[test]
    fn an_unterminated_paste_is_released_raw_past_the_cap() {
        let mut f = PasteFilter::default();
        let body = vec![b'a'; MAX_HELD_PASTE + 1];
        let mut chunk = PASTE_START.to_vec();
        chunk.extend_from_slice(&body);
        let got = f.feed(&chunk);
        assert_eq!(got, vec![keys(&chunk)]);
        assert_eq!(f.feed(b"z"), vec![keys(b"z")]);
    }

    #[test]
    fn shift_enter_becomes_a_carriage_return() {
        assert_eq!(translate_shift_enter(b"a\x1b[13;2ub"), b"a\rb");
        assert_eq!(translate_shift_enter(b"\x1b[27;2;13~"), b"\r");
    }

    fn file_in(dir: &TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, b"\x89PNG").unwrap();
        path
    }

    fn escaped(path: &Path) -> String {
        path.to_str().unwrap().replace(' ', "\\ ")
    }

    /// A `.png` under `$TMPDIR` is found, and `host_path` is the as-pasted
    /// `TempDir` path, not its canonical form — the guard must accept
    /// `$TMPDIR` on macOS (where it is a symlink) without returning the
    /// resolved path.
    #[test]
    fn a_file_that_exists_on_this_host_is_found() {
        let dir = TempDir::new().unwrap();
        let png = file_in(&dir, "Screenshot 2026-09-02.png");
        let body = escaped(&png);
        let found = pasted_files(body.as_bytes());
        assert_eq!(
            found,
            vec![PastedFile {
                span: 0..body.len(),
                host_path: png,
            }],
            "a pasted png under TempDir should be bridged with its non-canonical host_path"
        );
    }

    #[test]
    fn a_path_that_does_not_exist_here_is_left_alone() {
        // The remote-host guard: a Mac path pasted into a `dev shell` on an
        // ssh box names nothing there, so the paste must go through untouched.
        let body = b"/var/folders/8k/T/clipboard-2026-09-02-101500-abcd1234.png";
        assert!(pasted_files(body).is_empty());
        let mut framed = b"\x1b[200~".to_vec();
        framed.extend_from_slice(body);
        framed.extend_from_slice(b"\x1b[201~");
        assert_eq!(rewrite_paste(body, &[]), framed);
    }

    /// Decision 5: extension plays no part in qualification any more, so a
    /// `.pdf` under a paste root is bridged the same as a `.png` was.
    #[test]
    fn a_pdf_under_the_temp_dir_is_bridged() {
        let dir = TempDir::new().unwrap();
        let pdf = dir.path().join("notes.pdf");
        std::fs::write(&pdf, b"%PDF-1.4").unwrap();
        let found = pasted_files(pdf.to_str().unwrap().as_bytes());
        assert_eq!(
            found.len(),
            1,
            "a .pdf under TempDir should be bridged now that no extension check survives"
        );
        assert_eq!(
            found[0].host_path, pdf,
            "the bridged entry should name the pasted pdf"
        );
    }

    /// The location guard: a pasted system path must never be silently
    /// replaced by a copy of this host's own file, even though
    /// `/etc/passwd` is a real, world-readable, regular file under the cap.
    #[test]
    fn a_file_under_etc_is_left_alone() {
        let body = b"/etc/passwd";
        assert!(
            pasted_files(body).is_empty(),
            "a path under /etc must never be bridged, even when it names a real file"
        );
    }

    /// Proves the canonical path is what the guard checks: the symlink
    /// itself lives under an allowed root, and only resolving it exposes a
    /// target the guard must reject.
    #[test]
    fn a_symlink_into_a_system_file_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("hosts.txt");
        std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
        assert!(
            pasted_files(link.to_str().unwrap().as_bytes()).is_empty(),
            "a symlink under TempDir whose target resolves outside every paste root must not be bridged"
        );
    }

    /// The cap is compared with `<=`, not `<`, and survives the switch away
    /// from the extension allowlist.
    #[test]
    fn a_file_over_the_cap_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("big.bin");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_PASTED_FILE_BYTES + 1).unwrap();
        assert!(
            pasted_files(path.to_str().unwrap().as_bytes()).is_empty(),
            "a file one byte over the cap must not be bridged"
        );

        file.set_len(MAX_PASTED_FILE_BYTES).unwrap();
        assert_eq!(
            pasted_files(path.to_str().unwrap().as_bytes()).len(),
            1,
            "a file exactly at the cap must be bridged"
        );
    }

    /// The `is_file` check: a directory is never bridged, whatever it is named.
    #[test]
    fn a_directory_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("photos.png");
        std::fs::create_dir(&sub).unwrap();
        assert!(
            pasted_files(sub.to_str().unwrap().as_bytes()).is_empty(),
            "a directory must not be treated as a pasteable file"
        );
    }

    #[test]
    fn a_relative_path_is_left_alone() {
        let dir = TempDir::new().unwrap();
        file_in(&dir, "a.png");
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let found = pasted_files(b"a.png");
        std::env::set_current_dir(cwd).unwrap();
        assert!(found.is_empty());
    }

    /// Each word in a multi-file paste is found with the byte span it
    /// occupies in the original body, in order of appearance.
    #[test]
    fn several_dropped_files_are_each_found_with_their_spans() {
        let dir = TempDir::new().unwrap();
        let a = file_in(&dir, "a.png");
        let b = file_in(&dir, "b two.jpg");
        let body = format!("{} {}", escaped(&a), escaped(&b));
        let found = pasted_files(body.as_bytes());
        assert_eq!(found.len(), 2, "both pasted files should be found");
        assert_eq!(
            &body[found[0].span.clone()],
            escaped(&a),
            "the first span should cover exactly the first pasted path"
        );
        assert_eq!(
            &body[found[1].span.clone()],
            escaped(&b),
            "the second span should cover exactly the second pasted path"
        );
        assert_eq!(
            found[1].host_path, b,
            "the second entry should name the second pasted file"
        );
    }

    /// The all-or-nothing rule: a paste of only qualifying paths is still
    /// bridged in full, whether it names one file or several.
    #[test]
    fn a_paste_of_only_paths_is_bridged_whole() {
        let dir = TempDir::new().unwrap();
        let a = file_in(&dir, "a.png");
        let b = file_in(&dir, "b.png");

        let lone = pasted_files(escaped(&a).as_bytes());
        assert_eq!(
            lone.len(),
            1,
            "a lone qualifying path must still be bridged"
        );

        let body = format!("{} {}", escaped(&a), escaped(&b));
        let both = pasted_files(body.as_bytes());
        assert_eq!(
            both.len(),
            2,
            "a paste of only qualifying paths must bridge every one of them"
        );
    }

    /// The all-or-nothing rule: one plain word alongside a real path drops
    /// the whole paste, not just the word that failed to qualify.
    #[test]
    fn a_paste_mixing_a_path_and_plain_text_is_left_entirely_alone() {
        let dir = TempDir::new().unwrap();
        let png = file_in(&dir, "shot.png");
        let body = format!("{} take a look", escaped(&png));
        assert!(
            pasted_files(body.as_bytes()).is_empty(),
            "a paste mixing a real path with plain words must not bridge any of it"
        );
    }

    /// The motivating case: `scp <key> box:` must not bridge the key, since
    /// bridging only the path would copy a private key into the container
    /// and silently rewrite the command to run against the copy.
    #[test]
    fn a_pasted_ssh_key_alongside_an_scp_destination_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let key = file_in(&dir, "id_ed25519");
        let body = format!("scp {} box:", escaped(&key));
        assert!(
            pasted_files(body.as_bytes()).is_empty(),
            "scp <key> box: must not bridge the key, or the command would silently run against a copy"
        );
    }

    /// Bug: a word ending in an escaped character (the backslash-consuming
    /// branch) reported a span missing that last byte. The reported
    /// reproducer is a drag-and-dropped name ending in `)`.
    #[test]
    fn a_word_ending_in_an_escaped_character_has_a_full_span() {
        let dir = TempDir::new().unwrap();
        let path = file_in(&dir, "Screenshot (1)");
        let body = path
            .to_str()
            .unwrap()
            .replace(' ', "\\ ")
            .replace('(', "\\(")
            .replace(')', "\\)");
        let found = pasted_files(body.as_bytes());
        assert_eq!(
            found.len(),
            1,
            "the escaped name should resolve to exactly one file"
        );
        assert_eq!(
            &body[found[0].span.clone()],
            body,
            "the span must cover the whole escaped word, including its final escaped character"
        );
    }

    /// Bug: every macOS screenshot's name carries U+202F before the AM/PM,
    /// which `char::is_whitespace` calls a separator but no terminal escapes.
    /// The path split in two, the second half did not start with `/`, and the
    /// all-or-nothing rule dropped the whole paste.
    #[test]
    fn a_name_holding_a_narrow_no_break_space_stays_one_word() {
        let dir = TempDir::new().unwrap();
        let png = file_in(&dir, "Screenshot 2026-09-09 at 3.15.44\u{202f}PM.png");
        let body = escaped(&png);
        let found = pasted_files(body.as_bytes());
        assert_eq!(
            found,
            vec![PastedFile {
                span: 0..body.len(),
                host_path: png,
            }],
            "only ASCII whitespace separates words; U+202F belongs to the name"
        );
    }

    /// A single-quoted shell word is unquoted before it is resolved against
    /// the filesystem.
    #[test]
    fn a_single_quoted_name_is_unquoted() {
        let dir = TempDir::new().unwrap();
        let png = file_in(&dir, "it's.png");
        let body = format!("'{}'", png.to_str().unwrap().replace('\'', "'\\''"));
        let found = pasted_files(body.as_bytes());
        assert_eq!(found.len(), 1, "the quoted name should resolve to one file");
        assert_eq!(
            found[0].host_path, png,
            "the unquoted path should match the file on disk"
        );
    }

    /// The digest prefix is opaque and its length is not pinned here, but
    /// nothing in the result needs shell escaping, and the original name is
    /// still readable in it.
    #[test]
    fn the_container_path_needs_no_escaping() {
        let host = Path::new("/Users/me/Desktop/Screen Shot (1)'s.png");
        let path = container_paste_path(host);
        let stripped = path
            .strip_prefix(&format!("{CONTAINER_PASTE_DIR}/"))
            .expect("the container path must sit under CONTAINER_PASTE_DIR");
        assert!(
            stripped.ends_with("-Screen_Shot__1__s.png"),
            "the result must keep the sanitised basename after a digest prefix: {stripped}"
        );
        assert!(
            path.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-')),
            "the container path must need no shell escaping: {path}"
        );
    }

    /// Two files that share a basename but live in different directories
    /// must not collide on the same container path — the second paste must
    /// never silently overwrite the first's copy.
    #[test]
    fn same_named_files_in_different_directories_get_distinct_container_paths() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let a = dir_a.path().join("shot.png");
        let b = dir_b.path().join("shot.png");
        assert_ne!(
            container_paste_path(&a),
            container_paste_path(&b),
            "two same-named files from different directories must land at distinct container paths"
        );
    }

    /// Stability: the same host path always yields the same container path,
    /// so re-pasting it overwrites the earlier copy instead of accumulating
    /// a fresh one.
    #[test]
    fn the_same_host_path_yields_the_same_container_path_twice() {
        let host = Path::new("/Users/me/Desktop/shot.png");
        assert_eq!(
            container_paste_path(host),
            container_paste_path(host),
            "the same host path must yield the same container path on repeated calls"
        );
    }

    #[test]
    fn rewriting_keeps_the_rest_of_the_paste_byte_for_byte() {
        let body = b"see /a.png and /b.png now";
        let out = rewrite_paste(
            body,
            &[
                (4..10, "/tmp/dev-paste/a.png".into()),
                (15..21, "/tmp/dev-paste/b.png".into()),
            ],
        );
        assert_eq!(
            out,
            b"\x1b[200~see /tmp/dev-paste/a.png and /tmp/dev-paste/b.png now\x1b[201~"
        );
    }
}
