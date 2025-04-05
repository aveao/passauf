# passauf

Passauf is a Rust tool that lets you read eMRTDs¹ using a standard contactless reader (\<todo) or using a Proxmark 3. It supports BAC¹, and I plan to support PACE¹ soon.

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

At this time, PACE isn't implemented, so you cannot use `--can`.

## High-level overview of what this project does

Accessing an eMRTD works like so:

- On the physical layer and as the transmission protocol, we talk using ISO/IEC 14443 (Type A or B) with eMRTDs. This merely gets bytes flowing back and forth. This part is generally obscured from us, as it's handled by the contactless card reader, however, it does mean that you cannot use a reader intended for [ISO/IEC 15693 (Vicinity Cards)](https://en.wikipedia.org/wiki/ISO/IEC_15693) or LF¹.
    - For this we use the `pcsc` crate for regular smartcard readers, and regular serial communication for proxmark3 (thru the `serialport` crate).
- For application protocol, we use ISO/IEC 7816-4¹. This lets us use standardized commands (APDUs¹).
- We read the `EF.CardAccess` file if it is available, which contains the parameters for PACE and other types of authentication (Terminal Authentication, etc).
    - We parse this file using ASN.1.
- If it's not available, we attempt BAC, else we attempt PACE.
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
