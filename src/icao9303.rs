use log::warn;
use phf::phf_map;

#[derive(Debug)]
pub struct DataGroup {
    pub tag: u8,
    pub dg_num: u8,
    pub file_id: u16,
    pub description: &'static str, // length is 15b, ng is 1b
    pub pace_only: bool,
    pub eac_only: bool,
    // Whether the DG is under MF or eMRTD LDS1 applet.
    // For more info, see ICAO 9303 p10, page 39, figure 3
    // Alternatively: https://elixi.re/i/4tlij260gf43v.png
    // We basically can only read these if the applet is not selected.
    pub in_lds1: bool,
    pub parser: fn(Vec<u8>),
}

fn generic_parser(data: Vec<u8>) {
    warn!("Read file ({:?}b): {:?}", data.len(), data);
}

pub static AID_MRTD_LDS1: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];
pub static DATA_GROUPS: phf::Map<&'static str, &'static DataGroup> = phf_map! {
    "EF.COM" => &DataGroup{tag: 0x60, dg_num: 0, file_id: 0x011E, description: "Header and Data Group Presence Information", pace_only: false, eac_only: false, in_lds1: false, parser: generic_parser},
    "EF.CardAccess" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x011C, description: "SecurityInfos (PACE)", pace_only: true, eac_only: false, in_lds1: false, parser: generic_parser},
    "EF.CardSecurity" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x011D, description: "SecurityInfos for Chip Authentication Mapping (PACE)", pace_only: true, eac_only: false, in_lds1: false, parser: generic_parser},
    "EF.ATR/INFO" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x2F01, description: "Answer to Reset File", pace_only: false, eac_only: false, in_lds1: false, parser: generic_parser},
    "EF.DIR" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x2F00, description: "Directory", pace_only: false, eac_only: false, in_lds1: false, parser: generic_parser},
};

// static emrtd_dg_t dg_table[] = {
// //  tag    dg# fileid  filename           desc                                                  pace   eac    req    fast   parser                          dumper
//     {0x60, 0,  0x011E, "EF_COM",          "Header and Data Group Presence Information",         false, false, true,  true,  emrtd_print_ef_com_info,        NULL},
//     {0x61, 1,  0x0101, "EF_DG1",          "Details recorded in MRZ",                            false, false, true,  true,  emrtd_print_ef_dg1_info,        NULL},
//     {0x75, 2,  0x0102, "EF_DG2",          "Encoded Face",                                       false, false, true,  false, emrtd_print_ef_dg2_info,        emrtd_dump_ef_dg2},
//     {0x63, 3,  0x0103, "EF_DG3",          "Encoded Finger(s)",                                  false, true,  false, false, NULL,                           NULL},
//     {0x76, 4,  0x0104, "EF_DG4",          "Encoded Eye(s)",                                     false, true,  false, false, NULL,                           NULL},
//     {0x65, 5,  0x0105, "EF_DG5",          "Displayed Portrait",                                 false, false, false, false, emrtd_print_ef_dg5_info,        emrtd_dump_ef_dg5},
//     {0x66, 6,  0x0106, "EF_DG6",          "Reserved for Future Use",                            false, false, false, false, NULL,                           NULL},
//     {0x67, 7,  0x0107, "EF_DG7",          "Displayed Signature or Usual Mark",                  false, false, false, false, emrtd_print_ef_dg7_info,        emrtd_dump_ef_dg7},
//     {0x68, 8,  0x0108, "EF_DG8",          "Data Feature(s)",                                    false, false, false, true,  NULL,                           NULL},
//     {0x69, 9,  0x0109, "EF_DG9",          "Structure Feature(s)",                               false, false, false, true,  NULL,                           NULL},
//     {0x6a, 10, 0x010A, "EF_DG10",         "Substance Feature(s)",                               false, false, false, true,  NULL,                           NULL},
//     {0x6b, 11, 0x010B, "EF_DG11",         "Additional Personal Detail(s)",                      false, false, false, true,  emrtd_print_ef_dg11_info,       NULL},
//     {0x6c, 12, 0x010C, "EF_DG12",         "Additional Document Detail(s)",                      false, false, false, true,  emrtd_print_ef_dg12_info,       NULL},
//     {0x6d, 13, 0x010D, "EF_DG13",         "Optional Detail(s)",                                 false, false, false, true,  NULL,                           NULL},
//     {0x6e, 14, 0x010E, "EF_DG14",         "Security Options",                                   false, false, false, true,  NULL,                           NULL},
//     {0x6f, 15, 0x010F, "EF_DG15",         "Active Authentication Public Key Info",              false, false, false, true,  NULL,                           NULL},
//     {0x70, 16, 0x0110, "EF_DG16",         "Person(s) to Notify",                                false, false, false, true,  NULL,                           NULL},
//     {0x77, 0,  0x011D, "EF_SOD",          "Document Security Object",                           false, false, false, false, NULL,                           emrtd_dump_ef_sod},
//     {0xff, 0,  0x011C, "EF_CardAccess",   "PACE SecurityInfos",                                 true,  false, true,  true,  emrtd_print_ef_cardaccess_info, NULL},
//     {0xff, 0,  0x011D, "EF_CardSecurity", "PACE SecurityInfos for Chip Authentication Mapping", true,  false, false, true,  NULL,                           NULL},
//     {0x00, 0,  0, NULL, NULL, false, false, false, false, NULL, NULL}
// };

pub static EMRTD_EF_CARDACCESS: [u8; 2] = [0x01, 0x1C];
