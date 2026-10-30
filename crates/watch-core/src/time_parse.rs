//! Bounded Go RFC3339Nano parsing. No locale, host timezone or clock fallback.
pub fn rfc3339(value: &str) -> Option<f64> {
    if !value.is_ascii() || !(20..=64).contains(&value.len()) || value.as_bytes()[10] != b'T' {
        return None;
    }
    let integer = |s: &str| {
        if s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse::<i64>().ok()
        } else {
            None
        }
    };
    if &value[4..5] != "-" || &value[7..8] != "-" || &value[13..14] != ":" || &value[16..17] != ":"
    {
        return None;
    }
    let year = integer(&value[..4])?;
    let month = integer(&value[5..7])?;
    let day = integer(&value[8..10])?;
    let hour = integer(&value[11..13])?;
    let minute = integer(&value[14..16])?;
    let second = integer(&value[17..19])?;
    if year < 1 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = [
        31,
        if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > days[month as usize - 1] {
        return None;
    }
    let suffix = &value[19..];
    let tz_start = suffix.find(['Z', '+', '-'])?;
    let (fraction, zone) = suffix.split_at(tz_start);
    let fractional = if fraction.is_empty() {
        0.0
    } else {
        let digits = fraction.strip_prefix('.')?;
        if digits.is_empty() || !digits.bytes().all(|v| v.is_ascii_digit()) {
            return None;
        }
        let count = digits.len().min(6);
        integer(&digits[..count])? as f64 / 10u32.pow(count as u32) as f64
    };
    let offset = if zone == "Z" {
        0
    } else {
        if zone.len() != 6 || &zone[3..4] != ":" || !matches!(&zone[..1], "+" | "-") {
            return None;
        }
        let hours = integer(&zone[1..3])?;
        let minutes = integer(&zone[4..6])?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        (hours * 3600 + minutes * 60) * if zone.starts_with('-') { -1 } else { 1 }
    };
    // Gregorian civil date to Unix days; the supported range keeps all arithmetic in i64.
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let shifted = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    Some((days * 86400 + hour * 3600 + minute * 60 + second - offset) as f64 + fractional)
}
