# passauf for Android

An Android app that reads eMRTDs over the phone's own NFC radio, using the
passauf crate in the parent directory as its engine. It authenticates with PACE
or BAC, reads and parses every file the document offers, checks each data group
against EF.SOD, and writes the raw files out so you can take them somewhere
else.

The Rust library does all of the eMRTD work. Android only supplies the
transport: it holds the `IsoDep` connection and hands each APDU to the chip.

## What it does

- **Authenticate.** You type in what is printed on the document: either the
  document number, date of birth and date of expiry, or the CAN. PACE is used
  when the document offers a variant passauf supports, and BAC otherwise. A CAN
  needs PACE, so it will not work on a BAC-only document.
- **Read.** Every file EF.COM lists, plus EF.CardAccess, EF.CardSecurity,
  EF.COM and EF.SOD. The image data groups are large and slow, so there is a
  switch for leaving them out.
- **Validate.** Every data group that was read is hashed and held against
  EF.SOD, PACE-CAM's Chip Authentication check is completed against
  EF.CardSecurity or DG14 when the document uses it, and the MRZ's check digits
  are recomputed. See [what this does not prove](#what-validation-does-not-prove).
- **Dump.** Each file is written to the app's own storage as `.bin`, and the
  images inside DG2, DG5 and DG7 are written out alongside them as `.jpeg` or
  `.jp2`. The results screen can share one file or all of them.

Android's `BitmapFactory` has no JPEG 2000 decoder, and a great many issuers
encode DG2 that way, so the app borrows passauf's: each portrait is tried with
BitmapFactory first, which is hardware-accelerated and covers the JPEG half of
documents, and then with the library's own decoder. DG2 is preferred over DG5,
and only an image neither can read shows as saved-but-not-displayable.

There is no MRZ scanner yet. Everything is typed in by hand.

## Building

You need:

- The Android SDK with **NDK** installed (Android Studio: *SDK Manager > SDK
  Tools > NDK (Side by side)*).
- A **Rust toolchain**, 1.92 or newer. `build-rust.sh` adds the Android targets
  itself if they are missing.
- **JDK 17**.

Then:

```bash
cd android
./gradlew assembleDebug
```

Gradle cross-compiles the Rust library first, so a clean checkout builds
everything in one go. The APK lands in `app/build/outputs/apk/debug/`.

To install it on a connected phone:

```bash
./gradlew installDebug
```

### Speeding up the build

By default the Rust library is built for all three shipped ABIs. Building only
your own device's is much quicker:

```bash
./gradlew assembleDebug -Ppassauf.rustAbis=arm64-v8a
```

Or set `passauf.rustAbis` in `gradle.properties`. To skip the Rust build
entirely, when you know it is already up to date:

```bash
./gradlew assembleDebug -Ppassauf.skipRustBuild=true
```

### Building the library by hand

`build-rust.sh` works on its own, and is the thing to run when a cargo error
needs reading properly:

```bash
./build-rust.sh                    # every ABI, release
./build-rust.sh --debug arm64-v8a  # one ABI, debug
```

It writes `app/src/main/jniLibs/<abi>/libpassauf.so`, which is where Gradle
picks it up from. That directory is generated, and is not in the repository.

If the NDK is somewhere unusual, set `ANDROID_NDK_HOME`; otherwise the script
finds the newest one under `$ANDROID_HOME/ndk`.

## How the two halves fit together

The Rust side builds with `--no-default-features --features android`: no PC/SC,
no Proxmark, no CLI, and a JNI entry point instead. It exposes exactly one
function:

```
Java_zone_ave_passauf_PassaufNative_nativeReadDocument(
    optionsJson: String,
    transceiver: Transceiver,
    progress: ProgressListener?,
) -> String
```

`Transceiver.transceive(ByteArray): ByteArray?` is called for every APDU, and
`IsoDep.transceive` is what the app puts behind it. Returning `null` rather than
throwing is how the app says the document left the field. Progress messages come
back through `ProgressListener` while the read runs, and everything the read
established comes back as one JSON document, including passauf's own log.

Keeping the boundary one string wide means a data group passauf learns to parse
does not need a matching Kotlin class: unrecognized parser output arrives as
label/value rows and the app displays it as-is.

`src/ffi/` in the crate root holds the Rust side of this; `PassaufNative.kt`
holds the Kotlin side.

## What validation does not prove

The app is careful about this on screen, and it is worth repeating here.

What is checked:

- **The data groups agree with EF.SOD.** Every file that was read is hashed with
  the digest EF.SOD names and compared. A single altered byte fails.
- **EF.COM and EF.SOD agree about which data groups exist.** EF.COM is not
  covered by EF.SOD's signature, so a data group quietly dropped from its list
  would otherwise go unnoticed. The app says when the two disagree.
- **The chip is not a copy**, when the document supports PACE with Chip
  Authentication Mapping. A pass proves the chip holds the private key belonging
  to the Chip Authentication key it published.

What is **not** checked, and this is the important gap:

- **EF.SOD's signature.** Nothing verifies that a country signed this document.
  Everything above shows the document is internally consistent — that its parts
  match each other — not that anyone issued it. A document built from scratch,
  with its own EF.SOD covering its own data groups, passes every check the app
  currently makes.
- **Certificate chains.** Full Passive Authentication means verifying EF.SOD's
  signature against the Document Signer certificate it carries, verifying that
  against a Country Signing CA certificate from an ICAO masterlist, and checking
  the whole chain for revocation and validity dates. None of that exists yet, on
  either side of the JNI boundary. It is the next thing worth building: without
  it, "all data groups match EF.SOD" is a statement about consistency and
  nothing more. ICAO 9303 p11 section 4.4.3.5.2 also requires Passive
  Authentication alongside Chip Authentication Mapping before a CAM pass means
  the chip is genuine, so the two are tied together.

## Privacy

Everything happens on the phone. There is no network permission and nothing
leaves the device unless you explicitly share a file.

A document's data groups carry the holder's name, date of birth and face. A
face is biometric data, so how long a copy sits on the phone matters, and the
answer is: not long, and never longer than one document.

A read writes its files to `cache/documents/<timestamp>-<document number>/`,
under the cache rather than the app's data directory. That means:

- **One document at a time.** Starting a read deletes the previous read's
  files, and so does opening the app, which also clears anything a crash left
  behind.
- **Delete now if you want.** The results screen says how many files are on the
  phone and has a button to remove them immediately.
- **Never backed up.** Cache is excluded from cloud backup and device transfer
  by the platform, and `data_extraction_rules.xml` excludes everything anyway.
- **Reclaimable.** The system may delete cache under storage pressure at any
  time, which is the correct behaviour for files nobody has exported.

Files are deliberately *not* deleted when you simply navigate back from a
result. Sharing hands the receiving app a content URI it may not have finished
reading, and deleting underneath it would break the export you just asked for.
The next read, the next app start, or the delete button clears them instead.

## Layout

```
android/
├── build-rust.sh                    cross-compiles the crate into jniLibs
├── app/src/main/
│   ├── AndroidManifest.xml
│   └── java/zone/ave/passauf/
│       ├── PassaufNative.kt         the JNI binding and the report's shape
│       ├── ReaderViewModel.kt       form state, NFC tag handling, the read
│       ├── MainActivity.kt          reader mode and the screen to show
│       ├── Sharing.kt               handing files to the share sheet
│       └── ui/                      the three screens and the theme
└── gradle/libs.versions.toml        dependency versions
```
