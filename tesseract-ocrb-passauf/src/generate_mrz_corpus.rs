//! Generates machine readable zones to train a text recogniser on.
//!
//! A recogniser only ever sees one row at a time, so this emits rows rather than
//! documents: one per line, ready for text2image to render.
//!
//! Every row is built the way a real one is, with check digits from the library's own
//! [`icao9303::calculate_check_digit`]. That matters less for training the recogniser,
//! which cares about glyphs, than it does for evaluating it: a row that reads back
//! correctly can be handed straight to the parser and has to come out whole. It also
//! means the corpus exercises exactly the character distribution real documents have,
//! rather than one imagined for the occasion.
//!
//! Run with:
//!
//! ```text
//! cargo run --example generate_mrz_corpus -- 20000 > corpus.txt
//! ```

use passauf::icao9303::calculate_check_digit;
use passauf::types::MRZ;
use rand::RngExt;

const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

/// Real issuing states, plus the specimen code the standard's own examples use.
///
/// Held to a list rather than three random letters so the corpus looks like traffic a
/// document actually carries, and so common codes appear often enough to be learned.
const STATES: &[&str] = &[
    "UTO", "DEU", "TUR", "GBR", "FRA", "ITA", "ESP", "NLD", "POL", "USA", "CAN", "AUS", "JPN",
    "CHE", "AUT", "SWE", "NOR", "DNK", "BEL", "PRT", "GRC", "IRL", "CZE", "HUN", "ROU", "BGR",
    "HRV", "FIN", "EST", "LVA", "LTU", "SVK", "SVN", "D<<",
];

fn pick(pool: &[u8]) -> char {
    return pool[rand::rng().random_range(0..pool.len())] as char;
}

fn repeat(pool: &[u8], length: usize) -> String {
    return (0..length).map(|_| pick(pool)).collect();
}

/// Pads with the filler character, which is most of what an MRZ is made of.
fn pad(text: &str, width: usize) -> String {
    let mut padded = text.to_string();
    while padded.chars().count() < width {
        padded.push('<');
    }
    padded.truncate(width);
    return padded;
}

/// A name field, as `SURNAME<<GIVEN<NAMES` followed by filler.
///
/// The lengths vary widely on purpose. Filler runs are where a recogniser trained on
/// ordinary prose falls over, and a corpus of uniformly long names would never produce
/// the short runs, nor a corpus of short ones the runs of twenty and more.
fn name_field(width: usize) -> String {
    let mut rng = rand::rng();
    let surname = repeat(LETTERS, rng.random_range(2..=12));
    let given_count = rng.random_range(1..=3);
    let given: Vec<String> = (0..given_count)
        .map(|_| repeat(LETTERS, rand::rng().random_range(2..=10)))
        .collect();
    return pad(&format!("{}<<{}", surname, given.join("<")), width);
}

/// YYMMDD, kept to dates that exist.
fn date() -> String {
    let mut rng = rand::rng();
    return format!(
        "{:02}{:02}{:02}",
        rng.random_range(0..100),
        rng.random_range(1..=12),
        rng.random_range(1..=28)
    );
}

/// A document number as printed, which issuers spell in every style there is.
fn document_number() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(6..=9);
    return match rng.random_range(0..3) {
        // All digits, which is the common case.
        0 => repeat(DIGITS, length),
        // A letter or two up front, which is the other common case.
        1 => format!(
            "{}{}",
            repeat(LETTERS, rng.random_range(1..=2)),
            repeat(DIGITS, length - 1)
        ),
        // Thoroughly mixed, which some issuers do and a recogniser must not assume away.
        _ => repeat(ALPHABET_WITHOUT_FILLER, length),
    };
}

const ALPHABET_WITHOUT_FILLER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn sex() -> char {
    return match rand::rng().random_range(0..10) {
        0..=4 => 'M',
        5..=8 => 'F',
        _ => '<',
    };
}

fn state() -> &'static str {
    return STATES[rand::rng().random_range(0..STATES.len())];
}

fn with_check_digit(field: &str) -> String {
    return format!("{}{}", field, calculate_check_digit(&field.to_string()));
}

/// The two rows of a passport, per Doc 9303-4.
fn td3_rows() -> Vec<String> {
    let mut rows = Vec::with_capacity(2);
    let document_code = if rand::rng().random_range(0..10) == 0 {
        format!("P{}", pick(LETTERS))
    } else {
        "P<".to_string()
    };
    rows.push(format!("{}{}{}", document_code, state(), name_field(39)));

    let number = with_check_digit(&pad(&document_number(), 9));
    let birth = with_check_digit(&date());
    let expiry = with_check_digit(&date());
    // Often empty, sometimes a personal number, because both are everywhere.
    let optional = if rand::rng().random_range(0..2) == 0 {
        pad("", 14)
    } else {
        pad(&repeat(ALPHABET_WITHOUT_FILLER, rand::rng().random_range(4..=14)), 14)
    };
    let optional_check = calculate_check_digit(&optional);

    let lower = format!(
        "{}{}{}{}{}{}{}",
        number,
        state(),
        birth,
        sex(),
        expiry,
        optional,
        optional_check
    );
    let composite =
        calculate_check_digit(&[&lower[0..10], &lower[13..20], &lower[21..43]].concat());
    rows.push(format!("{}{}", lower, composite));
    return rows;
}

/// The three rows of an identity card, per Doc 9303-5.
fn td1_rows() -> Vec<String> {
    let document_code = match rand::rng().random_range(0..3) {
        0 => "I<".to_string(),
        1 => "ID".to_string(),
        // Residence permits, which is what a German one is and what the app has to
        // recognise before it touches a chip.
        _ => "AR".to_string(),
    };

    let number = with_check_digit(&pad(&document_number(), 9));
    let optional_one = if rand::rng().random_range(0..2) == 0 {
        pad("", 15)
    } else {
        pad(
            &repeat(ALPHABET_WITHOUT_FILLER, rand::rng().random_range(1..=15)),
            15,
        )
    };
    let upper = format!("{}{}{}{}", document_code, state(), number, optional_one);

    let birth = with_check_digit(&date());
    let expiry = with_check_digit(&date());
    let optional_two = pad("", 11);
    let middle_base = format!("{}{}{}{}{}", birth, sex(), expiry, state(), optional_two);
    let composite = calculate_check_digit(
        &[
            &upper[5..30],
            &middle_base[0..7],
            &middle_base[8..15],
            &middle_base[18..29],
        ]
        .concat(),
    );

    return vec![
        upper,
        format!("{}{}", middle_base, composite),
        name_field(30),
    ];
}

fn main() {
    let wanted: usize = std::env::args()
        .nth(1)
        .and_then(|count| count.parse().ok())
        .unwrap_or(10000);

    let mut rows: Vec<String> = Vec::with_capacity(wanted + 3);
    let mut rejected = 0usize;

    while rows.len() < wanted {
        // Passports are what most people point a camera at, but identity cards carry
        // three rows instead of two and a different set of field widths, so they are
        // worth better than a token share.
        let document = if rand::rng().random_range(0..10) < 6 {
            td3_rows()
        } else {
            td1_rows()
        };

        // Every document goes back through the parser before it is written out. The
        // corpus is only worth anything if a row that reads back correctly can be handed
        // to the parser and come out whole, and a composite check digit computed over
        // the wrong span is the easiest mistake in the standard to make. Getting it
        // wrong here would train the recogniser on rows no real document carries and
        // then measure it against them, which would look like success.
        if MRZ::from_recognized_lines(&document).is_err() {
            rejected += 1;
            assert!(
                rejected < 100,
                "the generator is producing zones the parser rejects, which means a check \
                 digit is being computed over the wrong span"
            );
            continue;
        }

        rows.extend(document);
    }
    rows.truncate(wanted);

    eprintln!("{} rows written, {} documents rejected.", rows.len(), rejected);
    println!("{}", rows.join("\n"));
}
