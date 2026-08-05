#!/usr/bin/env python3
"""
Generate src/types/country_codes.rs, the table naming the three-letter codes an
MRZ carries for nationality and issuing state.

Run it when a code changes hands or a name changes:

    python3 tools/country_codes.py

Two sources, neither of them memory. The bulk is ISO 3166, read out of the
iso-codes package rather than transcribed, so it can be regenerated and diffed
against a version anyone can install. The rest is ICAO 9303 Part 3 section 5,
which is where the codes that are not in ISO 3166 live — Germany's D, the
British nationality classes, the codes for people with no nationality to state.
Part 3 is a PDF and not machine readable in any useful sense, so those thirty
are transcribed below, table by table, in the order the standard prints them.

Requires the iso-codes package (Debian/Arch: iso-codes). Generated with 4.20.1.
"""
import json
import os

ISO_DIR = "/usr/share/iso-codes/json"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src/types/country_codes.rs")

# ICAO 9303 Part 3, edition 8, section 5: "Codes for Nationality, Place of Birth,
# Location of Issuing State/Authority and Other Purposes". Everything here is
# either absent from ISO 3166-1 or deprecated in it, which is exactly why the
# standard prints it.
#
# The wording is the standard's own "Entity (short name)" column, shortened only
# where that column is a definition rather than a name — the codes in Part E run
# to three lines each, and a row on a phone is not the place for them. The full
# text is in the comment beside each.
ICAO = [
    # Part A — codes not in ISO 3166-1.
    ("GBD", "British Overseas Territories Citizen"),
    ("GBN", "British National (Overseas)"),
    ("GBO", "British Overseas Citizen"),
    ("GBP", "British Protected Person"),
    ("GBS", "British Subject"),
    ("D", "Germany"),
    ("RKS", "Kosovo"),
    # Part B — reserved by the ISO 3166 maintenance agency.
    ("EUE", "European Union"),
    # Part C — United Nations travel documents.
    ("UNO", "United Nations Organization or one of its officials"),
    ("UNA", "United Nations specialized agency or one of its officials"),
    # "Resident of Kosovo to whom a travel document has been issued by the
    # United Nations Interim Administration Mission in Kosovo (UNMIK)".
    ("UNK", "Kosovo resident (UNMIK travel document)"),
    # Part D — other issuing authorities.
    ("XBA", "African Development Bank (ADB)"),
    ("XIM", "African Export-Import Bank (AFREXIM Bank)"),
    ("XCC", "Caribbean Community (CARICOM)"),
    ("XCE", "Council of Europe"),
    ("XCO", "Common Market for Eastern and Southern Africa (COMESA)"),
    ("XEC", "Economic Community of West African States (ECOWAS)"),
    ("XPO", "International Criminal Police Organization (INTERPOL)"),
    ("XES", "Organization of Eastern Caribbean States (OECS)"),
    ("XMP", "Parliamentary Assembly of the Mediterranean (PAM)"),
    ("XOM", "Sovereign Military Order of Malta"),
    ("XDC", "Southern African Development Community"),
    # Part E — persons without a defined nationality. These are the ones worth
    # having in words: three letters here are the difference between a country
    # and a person who has none, and nobody reads XXB as "refugee" unprompted.
    # "Stateless person, as defined in Article 1 of the 1954 Convention Relating
    # to the Status of Stateless Persons".
    ("XXA", "Stateless person (1954 Convention)"),
    # "Refugee, as defined in Article 1 of the 1951 Convention Relating to the
    # Status of Refugees as amended by the 1967 Protocol".
    ("XXB", "Refugee (1951 Convention)"),
    ("XXC", "Refugee, other than under XXB"),
    # "Person of unspecified nationality, for whom issuing State does not
    # consider it necessary to specify any of the codes XXA, XXB or XXC above".
    ("XXX", "Unspecified nationality"),
    # Part F — deprecated in ISO 3166, kept for backward compatibility.
    ("ANT", "Netherlands Antilles"),
    ("NTZ", "Neutral Zone"),
    # Part G — specimen documents. Not an issued code, and worth naming for
    # exactly that reason: a document claiming Utopia is a sample.
    ("UTO", "Utopia (specimen)"),
    # Part H — used by ICAO when signing a master list.
    ("IAO", "International Civil Aviation Organization (ICAO)"),
]

# Where this app's wording departs from the name in ISO 3166.
#
# ISO tracks what a state asks to be called, which is the right rule for a
# registry and not always the name the language has. It also inverts names so
# that they sort — "Korea, Republic of" — which is right for a list and wrong
# for a row on a phone that somebody is reading once. These are shown the way
# English usually writes them.
NAMES = {
    "TUR": "Turkey",
    "TWN": "Taiwan",
    "IRN": "Iran",
    "KOR": "South Korea",
    "PRK": "North Korea",
    # Two neighbouring states whose ISO names differ only by a clause, which is
    # the one case where the short form is clearer *and* less ambiguous.
    "COD": "DR Congo",
    "COG": "Congo-Brazzaville",
}


def load(table, key):
    with open(os.path.join(ISO_DIR, f"iso_{table}.json")) as fh:
        return {entry[key]: entry["name"] for entry in json.load(fh)[table]
                if key in entry}


def main():
    codes = {}
    # Withdrawn codes first: documents outlive the registry, and a passport
    # naming a state that no longer exists still has to read as something.
    codes.update(load("3166-3", "alpha_3"))
    # Then the current ones, which win where a code has been reused.
    codes.update(load("3166-1", "alpha_3"))
    # Then ICAO's, which win outright — they are the reason for this file.
    codes.update(dict(ICAO))
    codes.update({code: NAMES[code] for code in NAMES if code in codes})

    rows = "\n".join(
        f'    ("{code}", "{codes[code]}"),' for code in sorted(codes)
    )

    with open(OUT, "w") as fh:
        fh.write(f'''//! What the three-letter codes in an MRZ stand for.
//!
//! Generated by tools/country_codes.py. Do not edit by hand — edit the
//! generator and run it again.
//!
//! From ISO 3166-1 and ISO 3166-3 (via the iso-codes package, 4.20.1) and from
//! ICAO 9303 Part 3, edition 8, section 5, which is where the codes that are
//! not in ISO 3166 are defined: Germany's one-letter D, the British nationality
//! classes, the codes for people with no nationality to state, and the
//! organizations that issue travel documents of their own.

/// Every code and the entity it names, sorted so it can be searched.
///
/// Names are ISO 3166's, except where tools/country_codes.py says otherwise.
pub static COUNTRY_CODES: &[(&str, &str)] = &[
{rows}
];

/// What a code from an MRZ names, if anything.
///
/// None for a code no standard defines, which is not an error: the field is
/// three characters an issuer fills in, and passauf shows what it was given
/// either way.
pub fn describe_country_code(code: &str) -> Option<&'static str> {{
    return COUNTRY_CODES
        .binary_search_by(|(known, _)| (*known).cmp(code))
        .ok()
        .map(|index| COUNTRY_CODES[index].1);
}}
''')
    print(f"wrote {len(codes)} codes to {OUT}")


if __name__ == "__main__":
    main()
