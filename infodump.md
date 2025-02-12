# infodump

This file exists so if I get too rambly about a (hopefully) interesting topic, I can split it off from README.

## Terminology

You'll see me use terminology quite often. Here's some that may help:

- MRTD/eMRTD/eMROTD: "(Electronic) Machine Readable (Official) Travel Documents".
    - By default, "MRTD" refers to things like passports with MRZ fields.
    - "Electronic" means that it has a chip following the standards.
    - And at some point ICAO started adding "Official" in there for reasons unknown to me.
- ICAO: "International Civil Aviation Organization", the UN Agency governing individual civil aviation. Of course, we use MRTDs for non-aviation purposes on any civil international travel¹ too.
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

¹: Some other means of travel do not require it, and sometimes you can use a non-MRTD to travel too. There's a list in this file as I was feeling like enumerating knowledge.

## International travel without an eMRTD

I'm titling this as "travel without an eMRTD", and not "travle without a passport, because various countries let others' nationals enter with an ID alone. See the "International civil travel without passports" infodump section.

Here's some of the exclusions to travel without eMRTDs that I know:
- Military travel [does not require passports](https://www.ramstein.af.mil/About/Fact-Sheets/Display/Article/303670/travel-documents/), instead using things like Military IDs and NATO travel orders.
- Working seafarers can get [Seaman's books](https://en.wikipedia.org/wiki/Seafarers%27_Identity_Documents_Convention,_1958) and [cards](https://www.gov.uk/get-seamans-discharge-book-or-british-seamans-card), which let working them enter the ports they stop on, sometimes also having additional visa exemptions.
- Same applies to aircrew sometimes, [they may be able to use their airline IDs for visa exemption before their next flight](https://en.wikipedia.org/wiki/Visa_requirements_for_crew_members) (country-dependent).


However, official/diplomatic travel etc do [use their own passport types](https://en.wikipedia.org/wiki/Passport#Diplomatic_and_official_passports) and can still be required to get visas depending on state of diplomatic relations between countries. The weirdest such passports I know are:
- [Queen's/King's Messengers](https://en.wikipedia.org/wiki/King%27s_Messenger) in the UK, which transport some of the more sensitive [diplomatic baggage](https://en.wikipedia.org/wiki/Diplomatic_bag) for the UK.
- [Sovereign Military Order of Malta passport](https://en.wikipedia.org/wiki/Sovereign_Military_Order_of_Malta_passport). [SMOM](https://en.wikipedia.org/wiki/Sovereign_Military_Order_of_Malta) is a chivalric religious order that [runs the humanitarian aid organization Malteser International](https://en.wikipedia.org/wiki/Malteser_International) (you may have seen their ambulances around if you're in Germany). Despite the name, they're based in Italy, not Malta. Their diplomatic corps get the passport, and [it's accepted in some places](https://en.wikipedia.org/wiki/Visa_requirements_for_holders_of_passports_issued_by_the_Sovereign_Military_Order_of_Malta) which is impressive considering what they are (the map is outdated, check the list).

## International civil travel without passports

- Various trade blocs, regional cooperation unions, etc allow travel to other members with a national ID alone.
    - EU IDs can be used to travel to all of EU and Schengen for indefinite travel.
        - Non-EU Schengen member IDs (Norway, Iceland, Liechtenstein, Switzerland) can be used to travel to all of EU and Schengen for up to 90 days ([source](https://oslo.diplo.de/no-de/service/2640666-2640666)).
        - EU member states, and some EEA states, are required by EU law to issue eMRTDs by [Regulation (EU) 2019/1157](https://eur-lex.europa.eu/eli/reg/2019/1157/oj). As far as I know however, the old style IDs still suffice for travel inside EU.
    - Same for [Mercosur](https://en.wikipedia.org/wiki/Mercosur) (Southern Common Market / Mercado Común del Sur).
        - That said, only some issue eMRTDs as their IDs (Argentina does). Some don't (Brazil).
            - Argentina's pre-2024 IDs don't fully comply as they do not show the Chip Inside symbol (`[o]`), and MRZ does not match the correct alignment for document size. [It will only be properly compliant once 2024 series of IDs releases](https://regulaforensics.com/blog/argentine-id-card-processing/).
    - Same for [ECOWAS](https://en.wikipedia.org/wiki/ECOWAS) (Economic Community of West African States).
        - Unclear if any IDs are currently eMRTD (didn't have time to look it up), but [they're working on a common ID format called ENBIC](https://www.biometricupdate.com/202410/ecowas-agrees-to-accelerate-implementation-of-enbic-regional-id-card-for-stronger-integration) that appears to be intending to be an eMRTD.
    - Same for [GCC](https://en.wikipedia.org/wiki/Gulf_Cooperation_Council) (Gulf Cooperation Council).
        - [Emirates ID](https://en.wikipedia.org/wiki/Emirates_national_identity_card) is an eMRTD, based on pictures Qatar ID doesn't seem to be one, rest is unknown to me.
- Some countries IDs can be used for travel past their respective trade bloc too:
    - [French nationals can go to a number of non EU/schengen countries with an ID alone](https://www.bluevalet.fr/en/blog/42-countries-in-which-to-travel-without-a-passport), namely Albania, Andorra, Bosnia and Herzegovina, Serbia, Montenegro, Macedonia, Liechtenstein, Monaco, Turkey, Tunisia (only with a tour), and Egypt.
        - And probably more too, see the Wikipedia claims below.
    - [Turkey allows many countries' nationals to enter with an ID alone](https://www.mfa.gov.tr/countries-whose-citizens-are-allowed-to-enter-T%C3%BCrkiye-with-their-national-id_s.en.mfa), probably to encourage tourism.
        - Similarly, Turkish nationals can travel to [a few countries](https://www.turkishairlines.com/en-de/any-questions/visa-and-travel-requirements/) (list at bottom) with just a national ID card, which is an eMRTD.
    - [This Wikipedia article](https://en.wikipedia.org/wiki/National_identity_cards_in_the_European_Economic_Area_and_Switzerland) also claims...
        - that Egypt also allows various countries to enter with an ID alone. I cannot find recent sources for a list, but [Timatic confirms german nationals can use their ID](https://www.timaticweb2.com/integration/external-result/r1Y1GHaVw2x7MA4b-B-ph0OqdduJ9Q) (I didn't check the rest).
        - that one can travel to Anguilla, Dominica, Saint Lucia, Guernsey and Jersey with a French ID alone. No sources cited. [Timatic agrees partly for Anguilla, but restrictions apply on departure location](https://www.timaticweb2.com/integration/external-result/r1Y1GHaUkm1wYV8Zr0Wpg5m5_X8SPQ), I didn't check the rest.
        - that Gambia allows nationals of Belgium to travel with just an ID card. [Timatic agrees](https://www.timaticweb2.com/integration/external-result/r1Y1GHaWk21zMVhCrUSu037dlvNl-A).
        - that Greenland allows Nordic citizens to travel with any photo ID (?!). [Timatic kind of agrees](https://www.timaticweb2.com/integration/external-result/r1Y1GHaXwzggOw8f-0P_1kYDyzNZ_g).
- Generally: UK is a complex one. UK does not have a national ID system, nor do they have a mandate to carry ID. It's also arguable if UK is truly made up of multiple countries, or if they just call their version of states countries (not a rare concept, see cantons and prefectures).
    - UK citizens can however travel to Ireland without a passport by carrying other proof of UK citizenship (birth certificate?): https://www.gov.uk/foreign-travel-advice/ireland/entry-requirements
    - Similarly, [Republic of Ireland citizens can travel to UK with only an ID](https://www.citizensinformation.ie/en/government-in-ireland/ireland-and-the-uk/common-travel-area-between-ireland-and-the-uk/), though the official guidance notes that some carriers refuse anything but a passport.
    - [You can travel from Crown Dependencies (Jersey, Guernsey, Isle of Man) to UK without a passport](https://www.gov.uk/guidance/travelling-between-the-uk-and-ireland-isle-of-man-guernsey-or-jersey#crown-dependencies), but instead any form of official identity document, including passport cards, driver's licenses and armed forces IDs.

## Known applet IDs on the eMRTDs

- eMRTD LDS1: 0xA0000002471001 (ICAO 9303, 8th edition, p10)
- eMRTD LDS2 Travel Records: 0xA0000002472001 (ICAO 9303, 8th edition, p10)
- eMRTD LDS2 Visa Records: 0xA0000002472002 (ICAO 9303, 8th edition, p10)
- eMRTD LDS2 Additional Biometrics: 0xA0000002472003 (ICAO 9303, 8th edition, p10)
- Germany eID: 0xE80704007F0007030 (BSI TR-03127)
- Germany eSign: 0xA000000167455349474E (BSI TR-03127, unused)

LDS2 isn't widely supported to my knowledge.
