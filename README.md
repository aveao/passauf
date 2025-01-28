# passauf

Passauf is a Rust tool that lets you read eMRTDs¹ using a standard contactless reader or using a Proxmark 3 (\<in progress). It supports BAC¹ and PACE¹.

In late 2020, I wrote an eMRTD implementation for the [Iceman firmware of Proxmark 3](https://github.com/RfidResearchGroup/proxmark3), supporting only BAC. I have been meaning to support PACE since then, but as PACE requires implementing a lot of hash functions, I didn't really feel like doing it in C anymore². This is me fulfilling that dream, and hopefully making something that looks nicer in the process.

¹: See Terminology section.
²: The codebase was starting to look ugly, the memory management was annoying as always. I also was vary of pulling in an ASN.1 library, which only made writing code for it more complicated.

### Rough overview

Accessing an eMRTD works like so:

- On the physical layer and as the transmission protocol, we talk using ISO/IEC 14443 (Type A or B) with eMRTDs. This merely gets bytes flowing back and forth. This part is generally obscured from us, as it's handled by the contactless card reader, however, it does mean that you cannot use a reader intended for [ISO/IEC 15693 (Vicinity Cards)](https://en.wikipedia.org/wiki/ISO/IEC_15693) or LF¹.
    - For this we use the `pcsc` crate for regular smartcard readers, and regular serial communication for proxmark3 (thru the `serialport` crate).
- For application protocol, we use ISO/IEC 7816-4¹. This lets us use standardized commands.
- We read the `EF_CardAccess` file if it is available, which contains the parameters for PACE.
- If it's not available, we attempt BAC, else we attempt PACE.
- If authentication succeeds, we read the rest of the files we can access, parse them and check their checksums.
- Later: Certificate verification for the document.

¹: See Terminology section.

### Terminology

You'll see me use terminology quite often. Here's some that may help:

- MRTD/eMRTD/eMROTD: "(Electronic) Machine Readable (Official) Travel Documents".
    - By default, "MRTD" refers to things like passports with MRZ fields.
    - "Electronic" means that it has a chip following the standards.
    - And at some point ICAO started adding "Official" in there for reasons unknown to me.
- ICAO: "International Civil Aviation Organization", the UN Agency governing individual civil aviation. Of course, we use eMRTDs for non-aviation purposes too on any civil international travel³.
- VIZ: Visual Inspection Zone: The visible parts of the identity page(s) on an MRTD.
- MRZ: Machine Readable Zone: The part at the bottom of passports or back on IDs that are MRTDs with a lot of `<`s and [OCR-B](https://en.wikipedia.org/wiki/OCR-B) beauty.
- BAC: Basic Access Control: This is an access control mechanism for eMRTDs with a single predefined hash method (TODO) and a simple two-way handshake.
- PACE: TODO: It is optional to support PACE, but there are some documents that are PACE only, like German IDs and residence permit cards.
- [ICAO 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303): The main set of standards governing eMRTDs. There's more regional ones that diverge slightly. Example: ICAO 9303 mandates a gender field, German IDs exclude it for everyone, lacking the VIZ field and using < in MRZ to indicate gender of X (TODO: include the german DIN standard).
- [ISO/IEC 14443](https://en.wikipedia.org/wiki/ISO/IEC_14443): Basic communication layer for 13.56MHz proximity cards. There's Type A and B, which changes modulation. Most passports are Type A, but some are Type B.
- LF: Low frequency. For RFID purposes, this is 125kHz. Some people (incorrectly) call this "RFID" only.
- HF: High Frequency. For RFID purposes, this is 13.56MHz. Some people (incorrectly) call this "NFC" only.
    - NFC: Near Field Communications. This represents only a subset of HF, meaning different application protocols and tag types. This project will refrain from using this term as it is not relevant for us, and colloquial usage would only cause confusion. See this [helpful picture](https://upload.wikimedia.org/wikipedia/commons/3/33/NFC_Protocol_Stack.png), while we're also using ISO/IEC 14443 and ISO/IEC 7816-4, eMRTDs are not [NFC Type 4 Tags](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrfxlib/nfc/doc/type_4_tag.html).
- [ISO/IEC 7816-4](https://en.wikipedia.org/wiki/ISO/IEC_7816#7816-4:_Organization,_security_and_commands_for_interchange): This is the standard that is used for talking to smartcards, generally. It provides some standard commands, allowing us to get files and authenticate.
    - [APDU](https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit): Application protocol data unit. A concept of ISO/IEC 7816-4, a fixed data format.


³: Some other means of travel do not require it. I was on ADHD meds when I wrote this which can make me very interested in sharing information so check Infodump section if you want to see a list.

### Infodump

Here's some of the exclusions to travel without eMRTDs that I know:
- Military travel [does not require passports](https://www.ramstein.af.mil/About/Fact-Sheets/Display/Article/303670/travel-documents/), instead using things like Military IDs and NATO travel orders.
- Working seafarers can get [Seaman's books](https://en.wikipedia.org/wiki/Seafarers%27_Identity_Documents_Convention,_1958) and [cards](https://www.gov.uk/get-seamans-discharge-book-or-british-seamans-card), which let working them enter the ports they stop on, sometimes also having additional visa exemptions.
- Same applies to aircrew sometimes, [they may be able to use their airline IDs for visa exemption before their next flight](https://en.wikipedia.org/wiki/Visa_requirements_for_crew_members) (country-dependent).


However, official/diplomatic travel etc do [use their own passport types](https://en.wikipedia.org/wiki/Passport#Diplomatic_and_official_passports) and can still be required to get visas depending on state of diplomatic relations between countries. The weirdest such passports I know are:
- [Queen's/King's Messengers](https://en.wikipedia.org/wiki/King%27s_Messenger) in the UK, which transport some of the more sensitive [diplomatic baggage](https://en.wikipedia.org/wiki/Diplomatic_bag) for the UK.
- [Sovereign Military Order of Malta passport](https://en.wikipedia.org/wiki/Sovereign_Military_Order_of_Malta_passport). [SMOM](https://en.wikipedia.org/wiki/Sovereign_Military_Order_of_Malta) is a chivalric religious order that [runs the humanitarian aid organization Malteser International](https://en.wikipedia.org/wiki/Malteser_International) (you may have seen their ambulances around if you're in Germany). Despite the name, they're based in Italy, not Malta. Their diplomatic corps get the passport, and [it's accepted in some places](https://en.wikipedia.org/wiki/Visa_requirements_for_holders_of_passports_issued_by_the_Sovereign_Military_Order_of_Malta) which is impressive considering what they are (the map is outdated, check the list).

### The Name

Germans tend to shorten Passport¹ to Pass ("Haben Sie Ihren Pass dabei?" - "Do you have your passport with you?").

Pass auf translates to "watch out". There's no real implication there, it's just a silly pun, [I suspect everyone knows that their passport can be read by anyone with some authentication](https://xkcd.com/2501/).

¹: Full form is Reisepass, which roughly translates to Travel Pass (the pass part is [bit more complex](https://en.wiktionary.org/wiki/Pass#Etymology_2) than my simplification)

### Stylistic Choices

- I like explicit returns.
- There's some asserts in the code, which I will replace them with more rust-y alternatives later.
