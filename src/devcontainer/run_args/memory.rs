//! Sizes for `--memory` and `--memory-swap`, parsed the way the Docker CLI
//! parses them, and checked against the rules the daemon enforces at create.

use crate::error::DevError;

const KIB: i64 = 1024;
const MIB: i64 = 1024 * KIB;
const GIB: i64 = 1024 * MIB;

/// The daemon refuses a smaller memory limit (Docker's and Podman's
/// `linuxMinMemory`). A value under it is almost always a missing unit.
const MIN_MEMORY: i64 = 6 * MIB;

const UNLIMITED_SWAP: i64 = -1;

pub(super) fn parse_memory(flag: &str, value: &str) -> Result<i64, DevError> {
    ram_in_bytes(value).ok_or_else(|| invalid_size(flag, value))
}

/// The Docker CLI reads `-1` as unlimited swap before it parses a size.
pub(super) fn parse_memory_swap(flag: &str, value: &str) -> Result<i64, DevError> {
    if value == "-1" {
        return Ok(UNLIMITED_SWAP);
    }
    parse_memory(flag, value)
}

fn invalid_size(flag: &str, value: &str) -> DevError {
    DevError::InvalidConfig(format!(
        "`runArgs` flag `{flag}` has an invalid size `{value}`; expected a number with an optional unit b, k, m, g, t or p (for example `16g` or `512m`)"
    ))
}

/// The create-time checks the daemon makes on the final values. Running them
/// here fails `dev up` before the image build instead of after it. Zero is
/// what the daemon reads as no limit, so it passes.
pub(super) fn validate_limits(memory: Option<i64>, swap: Option<i64>) -> Result<(), DevError> {
    let explicit_zero_memory = memory == Some(0);
    let memory = memory.unwrap_or(0);
    let swap = swap.unwrap_or(0);
    if memory != 0 && memory < MIN_MEMORY {
        return Err(DevError::InvalidConfig(format!(
            "`runArgs` `--memory` is {}, under the 6m minimum Docker and Podman accept; add a unit, for example `512m`",
            format_size(memory)
        )));
    }
    if swap > 0 && memory == 0 {
        let memory_state = if explicit_zero_memory {
            "with `--memory` 0, which means no memory limit"
        } else {
            "without `--memory`"
        };
        return Err(DevError::InvalidConfig(format!(
            "`runArgs` sets `--memory-swap` {memory_state}; Docker and Podman refuse a swap limit unless a memory limit is set too"
        )));
    }
    if swap > 0 && swap < memory {
        return Err(DevError::InvalidConfig(format!(
            "`runArgs` `--memory-swap` ({}) is less than `--memory` ({}); `--memory-swap` is memory plus swap, so it must be at least `--memory`",
            format_size(swap),
            format_size(memory)
        )));
    }
    Ok(())
}

/// A byte count in Docker's own size syntax, in the largest binary unit that
/// divides it, so it reads well in messages and parses back to the same value.
pub fn format_size(bytes: i64) -> String {
    if bytes <= 0 {
        return bytes.to_string();
    }
    for (unit, scale) in [("g", GIB), ("m", MIB), ("k", KIB)] {
        if bytes % scale == 0 {
            return format!("{}{unit}", bytes / scale);
        }
    }
    format!("{bytes}b")
}

/// A port of go-units `RAMInBytes` (`parseSize` with binary units), which is
/// what `docker run --memory` uses. The number is everything up to the last
/// digit, dot or space; one space may separate it from the unit. The unit is
/// k, m, g, t or p, case-insensitive, optionally followed by `b` or `ib`, or a
/// bare `b`. A fraction is truncated after scaling. Values the Go parser takes
/// but Rust's float parser does not, such as hex floats, are rejected.
fn ram_in_bytes(value: &str) -> Option<i64> {
    let sep = value.rfind(|c: char| c.is_ascii_digit() || c == '.' || c == ' ')?;
    let number_end = if value.as_bytes()[sep] == b' ' {
        sep
    } else {
        sep + 1
    };
    let size: f64 = value[..number_end].parse().ok()?;
    if !size.is_finite() || size < 0.0 {
        return None;
    }
    let bytes = size * unit_multiplier(&value[sep + 1..])?;
    (bytes < i64::MAX as f64).then_some(bytes as i64)
}

fn unit_multiplier(suffix: &str) -> Option<f64> {
    if suffix.is_empty() {
        return Some(1.0);
    }
    if suffix.len() > 3 {
        return None;
    }
    let suffix = suffix.to_ascii_lowercase();
    if suffix == "b" {
        return Some(1.0);
    }
    let power = match suffix.as_bytes()[0] {
        b'k' => 1,
        b'm' => 2,
        b'g' => 3,
        b't' => 4,
        b'p' => 5,
        _ => return None,
    };
    match &suffix[1..] {
        "" | "b" | "ib" => Some(1024_f64.powi(power)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIB: i64 = 1024 * GIB;

    #[test]
    fn sizes_parse_like_go_units_ram_in_bytes() {
        for (size, bytes) in [
            ("0", 0),
            ("100", 100),
            ("100b", 100),
            ("100B", 100),
            ("1k", KIB),
            ("1kb", KIB),
            ("1KiB", KIB),
            ("512m", 512 * MIB),
            ("512MB", 512 * MIB),
            ("16g", 16 * GIB),
            ("16gb", 16 * GIB),
            ("16G", 16 * GIB),
            ("16GiB", 16 * GIB),
            ("16 g", 16 * GIB),
            ("1t", TIB),
            ("1p", 1024 * TIB),
            ("1.5g", 3 * GIB / 2),
            (".5g", GIB / 2),
            ("1.g", GIB),
            ("1e3", 1000),
            ("1.5", 1),
        ] {
            assert_eq!(ram_in_bytes(size), Some(bytes), "{size}");
        }
    }

    #[test]
    fn sizes_go_units_rejects_are_rejected() {
        for size in [
            "", "lots", "g", " g", "16x", "16gi", "1gbb", "1bb", "16  g", " 16g", "1.2.3g", "-1",
            "-1g", "nan g", "inf", "16e400",
        ] {
            assert_eq!(ram_in_bytes(size), None, "{size:?}");
        }
    }

    #[test]
    fn a_memory_limit_under_the_daemon_minimum_is_rejected_and_zero_is_not() {
        let err = validate_limits(Some(512), None).unwrap_err();
        let msg = format!("{err}");
        assert!(matches!(err, DevError::InvalidConfig(_)), "{msg}");
        assert!(msg.contains("is 512b") && msg.contains("`512m`"), "{msg}");

        validate_limits(Some(MIN_MEMORY), None).unwrap();
        validate_limits(Some(0), None).unwrap();
    }

    #[test]
    fn a_swap_limit_needs_a_memory_limit_unless_it_is_unlimited() {
        let err = validate_limits(None, Some(8 * GIB)).unwrap_err();
        assert!(format!("{err}").contains("without `--memory`"), "{err}");
        let err = validate_limits(Some(0), Some(8 * GIB)).unwrap_err();
        assert!(format!("{err}").contains("with `--memory` 0"), "{err}");

        validate_limits(None, Some(UNLIMITED_SWAP)).unwrap();
        validate_limits(None, Some(0)).unwrap();
    }

    #[test]
    fn a_swap_limit_below_the_memory_limit_is_rejected() {
        let err = validate_limits(Some(16 * GIB), Some(8 * GIB)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("(8g)") && msg.contains("(16g)"), "{msg}");

        validate_limits(Some(16 * GIB), Some(16 * GIB)).unwrap();
        validate_limits(Some(16 * GIB), Some(UNLIMITED_SWAP)).unwrap();
    }

    #[test]
    fn sizes_format_in_the_largest_unit_that_divides_them() {
        assert_eq!(format_size(16 * GIB), "16g");
        assert_eq!(format_size(1536 * MIB), "1536m");
        assert_eq!(format_size(3 * KIB), "3k");
        assert_eq!(format_size(512), "512b");
        assert_eq!(format_size(0), "0");
        assert_eq!(format_size(-1), "-1");
    }

    #[test]
    fn formatted_sizes_parse_back_to_the_same_bytes() {
        for bytes in [1, 512, KIB, 3 * KIB, 1536 * MIB, 16 * GIB, 5 * GIB + 1] {
            assert_eq!(ram_in_bytes(&format_size(bytes)), Some(bytes), "{bytes}");
        }
    }
}
