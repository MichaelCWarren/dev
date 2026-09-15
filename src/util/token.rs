/// 32 bytes of urandom, hex encoded. The only thing standing between an
/// agent relay's listener and anything else that can reach it, so it is read
/// straight from the kernel rather than derived from anything guessable.
/// Shared by `crate::cmux::agent` and `crate::ssh_agent`, the two relays that
/// mint one of these per session.
pub(crate) fn mint_token() -> Option<String> {
    use std::io::Read;

    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut buf)
        .ok()?;
    Some(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_differ_between_sessions() {
        let first = mint_token().expect("urandom is readable");
        assert_eq!(first.len(), 64);
        assert_ne!(first, mint_token().unwrap());
    }
}
