//! `--cpus`, held as nano-CPUs the way the daemon's `NanoCpus` field wants it.
//! Parsed with integer math so a value like `1.1` lands exactly.

use crate::error::DevError;

const NANO_PER_CPU: i64 = 1_000_000_000;
const FRACTION_DIGITS: usize = 9;

/// A positive decimal number of CPUs. Docker's CLI also takes exponents and
/// fractions like `1/2`; those are rejected here.
pub(super) fn parse_cpus(flag: &str, value: &str) -> Result<i64, DevError> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let all_digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !all_digits(whole) || !all_digits(fraction) {
        return Err(invalid_cpus(flag, value));
    }
    if fraction.len() > FRACTION_DIGITS {
        return Err(DevError::InvalidConfig(format!(
            "`runArgs` flag `{flag}` has a value `{value}` that is too precise; it takes at most {FRACTION_DIGITS} decimal places"
        )));
    }
    let nano = nano_cpus(whole, fraction).ok_or_else(|| invalid_cpus(flag, value))?;
    if nano == 0 {
        return Err(invalid_cpus(flag, value));
    }
    Ok(nano)
}

fn nano_cpus(whole: &str, fraction: &str) -> Option<i64> {
    let whole: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let padded = format!("{fraction:0<FRACTION_DIGITS$}");
    whole
        .checked_mul(NANO_PER_CPU)?
        .checked_add(padded.parse().ok()?)
}

fn invalid_cpus(flag: &str, value: &str) -> DevError {
    DevError::InvalidConfig(format!(
        "`runArgs` flag `{flag}` has an invalid value `{value}`; expected a positive number of CPUs (for example `8` or `1.5`)"
    ))
}

/// Nano-CPUs back as the shortest decimal, so `8` and `1.5` read as written.
pub fn format_cpus(nano: i64) -> String {
    let whole = nano / NANO_PER_CPU;
    let fraction = nano % NANO_PER_CPU;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:0FRACTION_DIGITS$}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_cpu_counts_parse_to_exact_nano_cpus() {
        for (value, nano) in [
            ("8", 8 * NANO_PER_CPU),
            ("1.5", 1_500_000_000),
            ("1.1", 1_100_000_000),
            ("0.5", 500_000_000),
            (".5", 500_000_000),
            ("2.", 2 * NANO_PER_CPU),
            ("0.000000001", 1),
            ("1.50", 1_500_000_000),
        ] {
            assert_eq!(parse_cpus("--cpus", value).unwrap(), nano, "{value}");
        }
    }

    #[test]
    fn non_positive_or_non_decimal_cpu_counts_are_rejected() {
        for value in [
            "",
            ".",
            "0",
            "0.0",
            "-1",
            "+1",
            "abc",
            "nan",
            "inf",
            "1e3",
            "1/2",
            "1.2.3",
            " 1",
            "1 ",
            "99999999999",
        ] {
            let msg = format!("{}", parse_cpus("--cpus", value).unwrap_err());
            assert!(
                msg.contains("`--cpus`") && msg.contains(&format!("`{value}`")),
                "{msg}"
            );
            assert!(msg.contains("positive number of CPUs"), "{msg}");
        }
    }

    #[test]
    fn more_than_nine_decimal_places_is_too_precise() {
        let msg = format!("{}", parse_cpus("--cpus", "1.0000000001").unwrap_err());
        assert!(msg.contains("too precise"), "{msg}");
        parse_cpus("--cpus", "1.000000001").unwrap();
    }

    #[test]
    fn nano_cpus_format_as_the_shortest_decimal() {
        assert_eq!(format_cpus(8 * NANO_PER_CPU), "8");
        assert_eq!(format_cpus(1_500_000_000), "1.5");
        assert_eq!(format_cpus(500_000_000), "0.5");
        assert_eq!(format_cpus(1), "0.000000001");
    }

    #[test]
    fn formatted_cpus_parse_back_to_the_same_nano_cpus() {
        for nano in [
            1,
            500_000_000,
            1_100_000_000,
            8 * NANO_PER_CPU,
            12_345_678_901,
        ] {
            assert_eq!(parse_cpus("--cpus", &format_cpus(nano)).unwrap(), nano);
        }
    }
}
