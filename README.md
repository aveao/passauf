# passauf

Passauf is a Rust tool that lets you read eMRTDs¹ using a standard contactless reader (\<todo) or using a Proxmark 3. It supports BAC¹ and PACE¹.

It is also a library, and there is an Android app built on it under [`android/`](android/) that reads documents over the phone's own NFC radio.

![](https://elixi.re/i/7vim01so3o.png)

In late 2020, I wrote an eMRTD implementation for the [Iceman firmware of Proxmark 3](https://github.com/RfidResearchGroup/proxmark3), supporting only BAC. I have been meaning to support PACE since then, but as PACE requires implementing a lot of additional crypto, I didn't really feel like doing it in C anymore². This is me fulfilling that dream, and hopefully making something that looks nicer in the process.

¹: See Terminology section in infodump.md.
²: The codebase was starting to look ugly, the memory management was annoying as always. I also was vary of pulling in libraries for handling BER-TLV or ASN.1, which only made writing code for it more complicated.

## Basic Usage

No binaries are provided at this time, so you're on your own for compiling the project.

Generally, `--help` exists for using the tool.

You can read a document and have its information printed in your terminal like so:
```bash
passauf -n documentnumber -b birthdate -e expiry
```

Dates must be entered in the YYMMDD format.

Example for a document with number of "A123B234", expiry of "12 Feb 2035" and birthdate of "01 Feb 2003/1903":
```bash
passauf -n A123B234 -b 030201 -e 350212
```

- By default, no files are dumped. To dump a document, you can add `--dump`. If you want the files to be put to a specific location, you can use `--dump path` syntax (like `--dump /tmp`), by default it'll use the current work directory.
    - When `--dump` is present, all files on the document that can be read are read, parsed, displayed and dumped.
    - When `--dump` isn't present, only the non-binary files are read, parsed and displayed.
- By default, we assume that you're using PCSC. To pick a different reader backend, you can use `--backend`, like `--backend pcsc` or `--backend proxmark`.
- By default we'll try to find a reader based on available USB devices. To pick a specific reader, you can use `--reader PATH`, like `--reader /dev/ttyACM0`.

Here's a relatively complete example showing all main flags in use:
```bash
passauf -n A123B234 -b 030201 -e 350212 --dump /tmp --backend proxmark --reader /dev/ttyACM0
```

PACE is used automatically when the document offers a variant passauf supports, falling back to BAC otherwise. `--can` uses the Card Access Number instead of the MRZ, which only works on documents that offer PACE.

See [Supported PACE algorithms](#supported-pace-algorithms) for what is and isn't implemented.

## High-level overview of what this project does

Accessing an eMRTD works like so:

- On the physical layer and as the transmission protocol, we talk using ISO/IEC 14443 (Type A or B) with eMRTDs. This merely gets bytes flowing back and forth. This part is generally obscured from us, as it's handled by the contactless card reader, however, it does mean that you cannot use a reader intended for [ISO/IEC 15693 (Vicinity Cards)](https://en.wikipedia.org/wiki/ISO/IEC_15693) or LF¹.
    - For this we use the `pcsc` crate for regular smartcard readers, and regular serial communication for proxmark3 (thru the `serialport` crate).
- For application protocol, we use ISO/IEC 7816-4¹. This lets us use standardized commands (APDUs¹).
- We read the `EF.CardAccess` file if it is available, which contains the parameters for PACE and other types of authentication (Terminal Authentication, etc).
    - We parse this file using ASN.1.
- If it offers a PACE variant we support, we attempt PACE, and otherwise fall back to BAC.
    - This requires us to know either all of document's expiry, date of birth and document number, or in case of PACE, alternatively the CAN¹.
    - For BAC, this is a "three-pass challenge-response protocol according to [ISO/IEC 11770-2] Key Establishment Mechanism 6 using 3DES [FIPS 46-3] as block cipher."
    - PACE is designed to be more secure, uses asymmetric crypto and lets documents support a number of algorithms. This makes it take more work to support it.
    - According to ICAO 9303 p11, a document can be BAC-only, BAC and PACE, and PACE-only. I have one of each to test with.
- Assuming authentication succeeds, we establish secure communication and read the rest of the files we can access.
    - After the authentication stage, all communications are encrypted.
    - We parse a large number of documents, which come in variety of shapes but are generally stored in BER-TLV structures.
        - As an extreme example of "variety of shapes": Reading the picture requires additionally implementing two other standards, ISO/IEC 19794-5 and ISO/IEC 39794, as they're used as the biometric container.
        - These parsed files are then displayed for the user to peruse.
    - We also dump the read files to a file if the user requests it.
        - Here, some files (like those containing biometrics) have custom dumpers, as having a raw jpeg you pull out of your passport has some cool factor to it.
- At the end, we validate the hashes of each file by comparing them against the hashes stored in `EF.SOD`.
- At a later point, I'll implement certificate verification for the document.

Helpful links from my last implementation:
- [I have a list of known quirks in eMRTD data](https://wf.lavatech.top/aves-tech-notes/emrtd-data-quirks), which implementations have to account for.
- [Here's a list of eMRTDs that are known to work with my other implementation, I suspect they'd all work with this too](https://github.com/RfidResearchGroup/proxmark3/issues/1117).

So far I only plan to support LDS1, but if I find any eMRTDs supporting LDS2 I may look into it.

¹: See Terminology section in infodump.md.

## Supported PACE algorithms

A PACE variant is a combination of a key agreement, a mapping, a cipher and a set of domain parameters. The document lists the combinations it accepts in `EF.CardAccess`, and passauf picks the first one it can run. If none of them are supported, it says which ones it saw and why each was rejected, then falls back to BAC where that is possible.

### Mappings

| Mapping | Supported | Notes |
| --- | --- | --- |
| Generic Mapping (GM) | Yes | |
| Integrated Mapping (IM) | Yes | |
| Chip Authentication Mapping (CAM) | Yes | Folds Chip Authentication into PACE. See [Chip Authentication Mapping](#chip-authentication-mapping) for what its result does and does not prove. |

### Key agreement and ciphers

| | Supported |
| --- | --- |
| ECDH | Yes |
| DH | Yes |
| 3DES-CBC-CBC | Yes |
| AES-CBC-CMAC-128 | Yes |
| AES-CBC-CMAC-192 | Yes |
| AES-CBC-CMAC-256 | Yes |

Both passwords are supported: the MRZ (document number, date of birth and date of expiry) and the CAN.

### Standardized domain parameters

These are the parameter IDs of ICAO 9303 part 11, section 9.5.1.

| ID | Parameters | Supported | Reason |
| --- | --- | --- | --- |
| 0 | 1024-bit MODP group, 160-bit subgroup | Yes | |
| 1 | 2048-bit MODP group, 224-bit subgroup | Yes | |
| 2 | 2048-bit MODP group, 256-bit subgroup | Yes | |
| 3–7 | — | — | Reserved for future use by the standard. |
| 8 | NIST P-192 | No | No Rust implementation available. |
| 9 | BrainpoolP192r1 | No | No Rust implementation available. |
| 10 | NIST P-224 | No | No Rust implementation available. Also barred from the Integrated Mapping by the standard, as its point encoding needs `p ≡ 3 mod 4`. |
| 11 | BrainpoolP224r1 | No | No Rust implementation available. |
| 12 | NIST P-256 | Yes | |
| 13 | BrainpoolP256r1 | Yes | The one German IDs use. |
| 14 | BrainpoolP320r1 | No | No Rust implementation available. |
| 15 | NIST P-384 | Yes | |
| 16 | BrainpoolP384r1 | Yes | |
| 17 | BrainpoolP512r1 | No | No Rust implementation available. |
| 18 | NIST P-521 | Yes | |
| 19–31 | — | — | Reserved for future use by the standard. |

The unsupported curves are the ones with no usable Rust crate behind them. Implementing them would mean hand-rolling curve arithmetic, which is a correctness and side-channel risk out of proportion to how rarely they appear in real documents. If crates appear for them, adding them is a matter of a line each in `src/pace/ecdh.rs` and `src/pace/domain.rs`.

### Chip Authentication Mapping

PACE-CAM proves the chip holds the private key belonging to the Chip Authentication key it presents, which a cloned chip cannot do. The chip returns `CA_IC = SK_IC⁻¹ · SK_Map,IC` encrypted under the session key, and passauf checks that `CA_IC · PK_IC` reproduces the mapping key the chip used during PACE.

`PK_IC` is read from **EF.CardSecurity**, which is where ICAO 9303 part 11 Appendix I takes it from, falling back to **DG14** for documents that publish it only there. This matters in practice: a German Reiseausweis für Ausländer publishes only its *Chip Authentication* key in DG14 and keeps the PACE-CAM key in EF.CardSecurity alone, so checking DG14 first finds nothing to match.

EF.CardSecurity needs PACE and lives at the master file, so PACE runs **before** the LDS1 applet is selected — the order ICAO 9303 part 11 Appendix J gives anyway — and the applet is then selected over secure messaging. BAC still selects the applet first, since it authenticates against it. EF.CardSecurity is a CMS `SignedData`; its `SecurityInfos` are reached through the eContent, and **its signature is not verified**, which again is Passive Authentication's job.

**A CAM pass is not proof the document is genuine.** It only proves the chip holds the private key for the key *it gave us*. Nothing yet establishes that key belongs to a real issuing authority — that is Passive Authentication's job, and ICAO 9303 part 11 section 4.4.3.5.2 requires PA alongside CAM for exactly this reason. `EF.SOD`'s hashes are checked (see below) but its signature is not, so treat a pass as "this chip is not a naive clone" rather than "this document is real".

### Also not implemented

- Explicit (non-standardized) domain parameters carried in a `PACEDomainParameterInfo`. Documents that use these are rejected with an explanation rather than guessed at.
- The trust half of Passive Authentication: verifying `EF.SOD`'s signature and building a certificate path to a Country Signing CA. See below for what *is* done.
- Terminal Authentication, and with it the `0x7F4C` Certificate Holder Authorization Template in MSE:Set AT. This is what would be needed to read EAC-protected data groups such as DG3 (fingerprints).

### Data group hashes (half of Passive Authentication)

`EF.SOD`, the Document Security Object, records a hash of every data group and is signed by the issuing country. passauf reads it, parses the `LDSSecurityObject` out of its CMS eContent, and checks each data group it read against the hash recorded for it. The hash algorithm is taken from the document rather than assumed; one we cannot compute is refused rather than guessed at.

It also reports data groups that `EF.SOD` covers but `EF.COM` omits. `EF.COM` is the file list the read loop follows, and it is *not* covered by `EF.SOD`'s signature — so an entry removed from it cannot be detected by that signature, and is worth flagging.

**This is only half of Passive Authentication.** `EF.SOD`'s own signature is not verified and no certificate path is built, so what a pass shows is that the data groups match what `EF.SOD` says they should be — internal consistency. It does not show that `EF.SOD` came from a real issuing authority: anyone able to re-sign the whole document produces a set that agrees with itself perfectly.

Closing that gap means verifying `EF.SOD`'s CMS signature against the Document Signer certificate it embeds, then building a path from that certificate to a Country Signing CA certificate held as a trust anchor. Part 12 is explicit that CSCA certificates arrive **out of band** — the ICAO PKD, national Master Lists, or bilateral exchange — so the hard part is distribution rather than cryptography. Until then the tool reports what it actually established, and says so on every run.

### Testing

The PACE implementation is checked against the worked examples in ICAO 9303 part 11: Appendix G.1 (ECDH Generic Mapping on BrainpoolP256r1 with AES-128), G.2 (DH Generic Mapping in the 1024-bit MODP group), H.1 (Integrated Mapping) and I (Chip Authentication Mapping). Every intermediate value the appendices publish is asserted, including the mapped generators, shared secrets, session keys and authentication tokens, so `cargo test` covers the cryptography without needing a document or a reader.

Two things in those appendices are worth knowing if you compare against them yourself:

- Appendix D quotes the BAC keys with DES parity bits adjusted. The key derivation function itself does not adjust them, since ICAO 9303 makes that step optional and the `des` crate ignores those bits, so the raw output differs in the low bit of most bytes.
- Appendix H says it reuses the MRZ-derived key from Appendix G, but the Kπ it lists is derived from the CAN `123456`. The text is wrong; the value is what an implementation has to reproduce.

## Using passauf as a library

The crate is split into a library (`src/lib.rs`) and the CLI binary that uses
it. `session::read_document` is the whole flow in one call: hand it something
that can exchange APDUs and what unlocks the document, and it authenticates,
reads every file, checks the data groups against EF.SOD and hands back a
`session::DocumentRead`.

The transport is yours to supply. `smartcard_abstractions::CallbackSmartcard`
takes a closure that gets a command APDU and returns the response, which is all
a reader has to do:

```rust
use passauf::session::{self, AccessKey, ReadOptions};
use passauf::smartcard_abstractions::{CallbackSmartcard, Smartcard};

let mut smartcard: Box<dyn Smartcard> = Box::new(CallbackSmartcard::new(|apdu| {
    // Whatever your reader does. Return the response APDU, status bytes and all.
    my_reader.transceive(apdu)
}));

let options = ReadOptions {
    access_key: AccessKey::Can("123456".to_string()),
    read_binary_files: true,
    ..Default::default()
};
let document = session::read_document(&mut smartcard, &options, &mut |_| {})?;
```

The PC/SC and Proxmark backends, the CLI and PACE are all features, so a build
that only needs the library can leave out whatever it does not use:

```bash
cargo build --no-default-features --features pace
```

The `android` feature adds JNI entry points for the app under `android/`; see
[its README](android/README.md) for how the two halves fit together. The
`jpeg2000` feature it pulls in adds a decoder for the images a document can
carry in DG2, DG5 and DG7, which is a display convenience and is never used
while reading or checking one.

### Dependency cooldown

New dependency versions wait a week before this project will take them. That is
the window a compromised publish lives in: the account gets taken over, the
world's lockfiles pick the release up within hours, and the yank comes later.
The policy is in [`cooldown.toml`](cooldown.toml) and is enforced by
[cargo-cooldown](https://crates.io/crates/cargo-cooldown):

```bash
cargo install --locked cargo-cooldown
cargo cooldown check          # or build / test / run
cargo cooldown update         # refresh Cargo.lock under the policy
```

Run those in place of the bare cargo command whenever the dependency graph
changes. A version that is too fresh fails the run and leaves `Cargo.lock`
alone rather than being quietly accepted.

## Proxmark3 support

### Background on Proxmark3

[Proxmark3](https://en.wikipedia.org/wiki/Proxmark3) is an RFID research tool.

To be more exact, it's a physical RFID interface that has an (EOL) Xilinx FPGA to handle RF, and an ARM core to facilitate communications between the FPGA and the computer. As it does not use an off-the-shelf HF or LF chip, it can do various non-standard actions, including sending commands that aren't standards-compliant, controlling field power, alongside simulating various standards. The hardware was originally designed about a decade ago, but got various upgrades over the years (while keeping the EOL FPGA), such as the [RDV4](https://lab401.com/en-de/products/proxmark-3-rdv4).

Bulk of the work of proxmark3 however lies in [the client](https://github.com/RfidResearchGroup/proxmark3), which has a large number of RF standards and tools built into it. As I said in the opening, I had originally built my eMRTD support into this client.

### Overview

For quite a few years now, I've been meaning to write a library to be able to use Proxmark as a regular smartcard reader (likely as a driver to use with PCSCd¹). The first part of that would always be through implementing a subset of its functionality on a project like this, and later I'd split it off at another time. This is that project (thanks to me misplacing my regular ACR122U reader).

I've only tested this code with an RDV4 running [the Iceman firmware](https://github.com/RfidResearchGroup/proxmark3) v4.19552 (2024-11-22), but it should hopefully work on any proxmark3 running Iceman firmware with capabilities version of 6 (so, [any build since December 2021](https://github.com/RfidResearchGroup/proxmark3/commit/69ea599fee3cd95474b7dfb79027760da312a8fa)).

Here's the list of features I plan to support (checkmarks indicate if it is implemented):

- [x] USB serial communications with a proxmark3
    - [x] Automatically detecting the serial port when not supplied.
- [ ] Bluetooth BSUART communications with a proxmark3
    - (This requires implementing proper CRC support alongside more generous timeouts)
- [x] NG and MIX format of commands and responses
- [x] Various basic commands (`CMD_PING`, `CMD_CAPABILITIES`, `CMD_HF_DROPFIELD`, `CMD_QUIT_SESSION`, `CMD_DEBUG_PRINT_STRING`)
    - [x] Adjacent helper functions (`pm3_ping`, `pm3_check_capabilities`, `pm3_quit_session`, `pm3_hf_drop_field`)
- [x] ISO/IEC 14443a support (`CMD_HF_ISO14443A_READER`, `pm3_exchange_14a_command`)
    - [ ] Support for parsing ATS and ATR for determining a higher timeout
    - [x] Helper function for selecting a card (`pm3_14a_select`)
    - [x] Helper function for exchanging APDUs (`pm3_exchange_apdu_14a`)
- [x] ISO/IEC 14443b support (`CMD_HF_ISO14443B_COMMAND`)
    - [x] Adjacent helper functions
    - [ ] Ability to select cards via different selection methods
- [x] Some sort of way to automatically detect 14a vs 14b? -> Implemented in the abstraction
- [ ] Support for `CMD_WTX` (wait time extension)
    - Unclear if this is necessary for this project, but it seems useful to have.
- [x] Better error handling
    - [x] Status code parsing past OK
    - [x] Graceful error handling

## The Name

Germans tend to shorten Passport¹ to Pass ("Haben Sie Ihren Pass dabei?" - "Do you have your passport with you?").

Pass auf translates to "watch out". There's no real implication there, it's just a silly pun, [I suspect everyone knows that their passport can be read by anyone with some authentication](https://xkcd.com/2501/).

¹: Full form is Reisepass, which roughly translates to Travel Pass (the pass part is [bit more complex](https://en.wiktionary.org/wiki/Pass#Etymology_2) than my simplification)

## Stylistic Choices

- I like explicit returns and use them a lot.
- This project requires `std`.
- There are some panics around that I intend to get rid of before late.
    - The JNI layer catches them rather than letting them unwind across the
      boundary, but they are still panics, and a `Result` would be better.
