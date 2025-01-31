# passauf

Passauf is a Rust tool that lets you read eMRTDs¹ using a standard contactless reader (\<todo) or using a Proxmark 3. It supports BAC¹ and PACE¹.

In late 2020, I wrote an eMRTD implementation for the [Iceman firmware of Proxmark 3](https://github.com/RfidResearchGroup/proxmark3), supporting only BAC. I have been meaning to support PACE since then, but as PACE requires implementing a lot of hash functions, I didn't really feel like doing it in C anymore². This is me fulfilling that dream, and hopefully making something that looks nicer in the process.

¹: See Terminology section.
²: The codebase was starting to look ugly, the memory management was annoying as always. I also was vary of pulling in an ASN.1 library, which only made writing code for it more complicated.

## Rough overview

Accessing an eMRTD works like so:

- On the physical layer and as the transmission protocol, we talk using ISO/IEC 14443 (Type A or B) with eMRTDs. This merely gets bytes flowing back and forth. This part is generally obscured from us, as it's handled by the contactless card reader, however, it does mean that you cannot use a reader intended for [ISO/IEC 15693 (Vicinity Cards)](https://en.wikipedia.org/wiki/ISO/IEC_15693) or LF¹.
    - For this we use the `pcsc` crate for regular smartcard readers, and regular serial communication for proxmark3 (thru the `serialport` crate).
- For application protocol, we use ISO/IEC 7816-4¹. This lets us use standardized commands (APDUs¹).
- We read the `EF_CardAccess` file if it is available, which contains the parameters for PACE.
    - We parse this file using ASN.1.
- If it's not available, we attempt BAC, else we attempt PACE.
    - This requires us to know either all of document's expiry, date of birth and document number, or in case of PACE, alternatively the CAN¹.
    - For BAC, this is a "three-pass challenge-response protocol according to [ISO/IEC 11770-2] Key Establishment Mechanism 6 using 3DES [FIPS 46-3] as block cipher."
    - PACE is designed to be more secure, uses asymmetric crypto and lets documents support a number of algorithms. This makes it take more work to support it.
    - According to ICAO 9303 p11, a document can be BAC-only, BAC and PACE, and PACE-only. I have one of each to test with.
- Assuming authentication succeeds, we establish secure communication and read the rest of the files we can access, parse them and verify their checksums.
    - After the authentication stage, all communications are encrypted.
    - Depending on user's requests, we may display them or dump them to a file.
- Later: Certificate verification for the document.

Helpful links from my last implementation:
- [I have a list of known quirks in eMRTD data](https://wf.lavatech.top/aves-tech-notes/emrtd-data-quirks), which implementations have to account for.
- [Here's a list of eMRTDs that are known to work with my other implementation, I suspect they'd all work with this too](https://github.com/RfidResearchGroup/proxmark3/issues/1117).

So far I only plan to support LDS1, but if I find any eMRTDs supporting LDS2 I may look into it.

¹: See Terminology section.

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
- [ ] Bluetooth BSUART communications with a proxmark3
    - (This requires implementing proper CRC support alongside more generous timeouts)
- [x] NG and MIX format of commands and responses
- [x] Various basic commands (`CMD_PING`, `CMD_CAPABILITIES`, `CMD_HF_DROPFIELD`, `CMD_QUIT_SESSION`, `CMD_DEBUG_PRINT_STRING`)
    - [x] Adjacent helper functions (`pm3_ping`, `pm3_check_capabilities`, `pm3_quit_session`, `pm3_hf_drop_field`)
- [x] ISO/IEC 14443a support (`CMD_HF_ISO14443A_READER`, `pm3_exchange_14a_command`)
    - [ ] Support for parsing ATS and ATR for determining a higher timeout
    - [x] Helper function for selecting a card (`pm3_14a_select`)
    - [x] Helper function for exchanging APDUs (`pm3_exchange_apdu_14a`)
- [ ] ISO/IEC 14443b support (`CMD_HF_ISO14443B_COMMAND`?)
- [ ] Some sort of way to automatically detect 14a vs 14b?
- [ ] Support for `CMD_WTX` (wait time extension)
    - Unclear if this is necessary for this project, but it seems useful to have.
- [ ] Better error handling
    - [ ] Status code parsing past OK
    - [ ] Graceful error handling

## Terminology

You'll see me use terminology quite often. Here's some that may help:

- MRTD/eMRTD/eMROTD: "(Electronic) Machine Readable (Official) Travel Documents".
    - By default, "MRTD" refers to things like passports with MRZ fields.
    - "Electronic" means that it has a chip following the standards.
    - And at some point ICAO started adding "Official" in there for reasons unknown to me.
- ICAO: "International Civil Aviation Organization", the UN Agency governing individual civil aviation. Of course, we use MRTDs for non-aviation purposes on any civil international travel³ too.
- VIZ: Visual Inspection Zone: The visible parts of the identity page(s) on an MRTD.
- MRZ: Machine Readable Zone: The part at the bottom of passports or back on IDs that are MRTDs with a lot of `<`s and [OCR-B](https://en.wikipedia.org/wiki/OCR-B) beauty.
- BAC: Basic Access Control: This is an access control mechanism for eMRTDs with a single predefined hash method (TODO) and a simple two-way handshake.
- PACE: TODO: It is optional to support PACE, but there are some documents that are PACE only, like German IDs and residence permit cards.
- [ICAO 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303): The main set of standards governing eMRTDs. There's more regional ones that diverge slightly. Example: ICAO 9303 mandates a gender field, German IDs exclude it for everyone, lacking the VIZ field and using < in MRZ to indicate gender of X. [See BSI TR-03110](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/tr-03110.html) for more info.
- [ISO/IEC 14443](https://en.wikipedia.org/wiki/ISO/IEC_14443): Basic communication layer for 13.56MHz proximity cards. There's Type A and B, which changes modulation. Most passports are Type A, but some are Type B.
- LF: Low frequency. For RFID purposes, this is 125kHz. Some people (incorrectly) call this "RFID" only.
- HF: High Frequency. For RFID purposes, this is 13.56MHz. Some people (incorrectly) call this "NFC" only.
    - NFC: Near Field Communications. This represents only a subset of HF, meaning different application protocols and tag types. This project will refrain from using this term as it is not relevant for us, and colloquial usage would only cause confusion. See this [helpful picture](https://upload.wikimedia.org/wikipedia/commons/3/33/NFC_Protocol_Stack.png), while we're also using ISO/IEC 14443 and ISO/IEC 7816-4, eMRTDs are not [NFC Type 4 Tags](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrfxlib/nfc/doc/type_4_tag.html).
- [ISO/IEC 7816-4](https://en.wikipedia.org/wiki/ISO/IEC_7816#7816-4:_Organization,_security_and_commands_for_interchange): This is the standard that is used for talking to smartcards, generally. It provides some standard commands, allowing us to get files and authenticate.
    - [APDU](https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit): Application protocol data unit. A concept of ISO/IEC 7816-4, a fixed data format.
- RF: Radio frequency. Not specifically referring to frequencies themselves, colloquially used as "radio communications".
- [PCSCd](https://linux.die.net/man/8/pcscd): A linux daemon for talking to smartcard interfaces.


³: Some other means of travel do not require it, and sometimes you can use a non-MRTD to travel too. I was having fun enumerating knowledge, so I put down a list in the [infodump.md](/infodump.md) if you're curious.

## The Name

Germans tend to shorten Passport¹ to Pass ("Haben Sie Ihren Pass dabei?" - "Do you have your passport with you?").

Pass auf translates to "watch out". There's no real implication there, it's just a silly pun, [I suspect everyone knows that their passport can be read by anyone with some authentication](https://xkcd.com/2501/).

¹: Full form is Reisepass, which roughly translates to Travel Pass (the pass part is [bit more complex](https://en.wiktionary.org/wiki/Pass#Etymology_2) than my simplification)

## Stylistic Choices

- I like explicit returns.
- There's some asserts in the code, which I will replace them with more rust-y alternatives later.
