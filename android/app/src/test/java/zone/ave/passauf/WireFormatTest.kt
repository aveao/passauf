package zone.ave.passauf

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The JSON crossing the JNI boundary, held to what the Rust side reads and
 * writes.
 *
 * Nothing here needs the native library. The point is that a field renamed on
 * one side without the other fails a test rather than turning into a silent
 * default at runtime, which is exactly how image reading got switched off.
 */
class WireFormatTest {

    /**
     * kotlinx omits a property still equal to its declared default unless told
     * otherwise, and Rust reads an absent field as *its* default. Between them
     * that turned `readBinaryFiles = true` into `false`, and DG2 was never read.
     */
    @Test
    fun `options a caller left at their defaults are still sent`() {
        val json = passaufJson.encodeToString(
            ReadOptions(accessKey = AccessKey.Can("123456")),
        )

        assertContains(json, "\"readBinaryFiles\":true")
        // info, not debug. At debug the read records the contents of every file, and
        // the app will offer that log to a file picker; it defaulted to debug once, and
        // this is here so it cannot drift back without saying so.
        assertContains(json, "\"logLevel\":\"info\"")
        assertFalse(json.contains("\"logLevel\":\"debug\""), json)
        // Nulls are the exception: Rust has its own default for an absent
        // dumpPath, and sending null would mean the same thing more loudly.
        assertFalse(json.contains("dumpPath"), json)
    }

    /** The tag and field names the Rust enum is spelled with. */
    @Test
    fun `both kinds of access key are spelled the way Rust reads them`() {
        val can = passaufJson.encodeToString(
            ReadOptions(accessKey = AccessKey.Can("123456")),
        )
        assertContains(can, "\"type\":\"can\"")
        assertContains(can, "\"value\":\"123456\"")

        val mrz = passaufJson.encodeToString(
            ReadOptions(
                accessKey = AccessKey.Mrz(
                    documentNumber = "A123B234",
                    dateOfBirth = "030201",
                    dateOfExpiry = "350212",
                ),
            ),
        )
        assertContains(mrz, "\"type\":\"mrz\"")
        assertContains(mrz, "\"documentNumber\":\"A123B234\"")
        assertContains(mrz, "\"dateOfBirth\":\"030201\"")
        assertContains(mrz, "\"dateOfExpiry\":\"350212\"")
    }

    /**
     * A report exactly as the Rust side serializes one, taken from the
     * `serializes_the_keys_the_app_expects` test in src/ffi/report.rs.
     */
    @Test
    fun `a report from the library decodes into every field`() {
        val report = passaufJson.decodeFromString<DocumentReport>(RUST_REPORT)

        assertTrue(report.ok)
        assertEquals("PACE", report.authentication?.method)
        assertEquals("PACE-ECDH-CAM-AES-CBC-CMAC-256", report.authentication?.algorithm)
        assertEquals("passed", report.chipAuthentication?.status)
        assertEquals("brainpoolP256r1", report.chipAuthentication?.curve)
        assertEquals("EF.CardSecurity", report.chipAuthentication?.source)

        assertEquals(true, report.integrity?.securityObjectRead)
        assertEquals("SHA-256", report.integrity?.hashAlgorithm)
        assertEquals(listOf(1L, 2L), report.integrity?.checked)
        assertEquals(emptyList(), report.integrity?.missingFromEfCom)

        assertEquals("MUSTERMANN", report.document?.surname)

        assertEquals(1, report.files.size)
        val file = report.files.first()
        assertEquals("EF.DG1", file.name)
        assertEquals("0x0101", file.fileId)
        assertEquals("matches", file.hashStatus)
        assertEquals(93, file.size)
        assertEquals(listOf("/tmp/x-EF_DG1.bin"), file.dumped)
        // Which of the dumped files are pictures comes from the library, not
        // from guessing at extensions here.
        assertEquals(emptyList(), file.images)
        assertEquals("MRZ", file.details.first().label)

        assertEquals(listOf("/tmp/x-EF_DG2-pic1.jpeg"), report.portraits)
        assertEquals(1, report.log.size)
        // Absent optionals are left out entirely rather than sent as null.
        assertEquals(null, report.error)
    }

    /**
     * The name on the front of the result is DG11's where there is one.
     *
     * The MRZ truncates a name that will not fit its rows, so a document that carries
     * both is carrying the short version and the full one, and the screen should be
     * showing the full one.
     */
    @Test
    fun `the name shown prefers DG11 over the MRZ`() {
        val fromMrz = passaufJson.decodeFromString<DocumentDetails>(
            """{"surname":"MUSTERMANN","givenNames":"ERIKA"}""",
        )
        assertEquals("ERIKA MUSTERMANN", fromMrz.displayName)

        val fromDg11 = passaufJson.decodeFromString<DocumentDetails>(
            """{"surname":"MUSTERMANN","givenNames":"ERIKA",
                "fullName":"ERIKA MARIA MUSTERMANN-SCHMIDT"}""",
        )
        assertEquals("ERIKA MARIA MUSTERMANN-SCHMIDT", fromDg11.displayName)
        // The zone's shorter copy stays reachable, since the screen shows both once
        // DG11 has supplied one of them.
        assertEquals("ERIKA MUSTERMANN", fromDg11.mrzName)

        // A document with neither has no name to show, and the screen says so itself.
        assertEquals(null, passaufJson.decodeFromString<DocumentDetails>("{}").displayName)
    }

    /** A read that failed before it got anywhere still has to decode. */
    @Test
    fun `a failure report decodes`() {
        val report = passaufJson.decodeFromString<DocumentReport>(
            """{"ok":false,"error":"Could not authenticate with the document",""" +
                """"files":[],"portraits":[],"warnings":[],"log":[]}""",
        )
        assertFalse(report.ok)
        assertEquals("Could not authenticate with the document", report.error)
        assertTrue(report.files.isEmpty())
    }

    private companion object {
        const val RUST_REPORT = """
            {"ok":true,
             "authentication":{"method":"PACE","algorithm":"PACE-ECDH-CAM-AES-CBC-CMAC-256"},
             "chipAuthentication":{"status":"passed","source":"EF.CardSecurity",
                                   "curve":"brainpoolP256r1"},
             "integrity":{"securityObjectRead":true,"hashAlgorithm":"SHA-256","consistent":true,
                          "checked":[1,2],"mismatched":[],"unchecked":[],"missingFromEfCom":[]},
             "document":{"surname":"MUSTERMANN","personalDetails":[],"documentDetails":[]},
             "files":[{"name":"EF.DG1","description":"Details recorded in MRZ","fileId":"0x0101",
                       "present":true,"size":93,"hashStatus":"matches",
                       "dumped":["/tmp/x-EF_DG1.bin"],"images":[],
                       "details":[{"label":"MRZ","value":"P<UTO..."}]}],
             "portraits":["/tmp/x-EF_DG2-pic1.jpeg"],
             "warnings":[],
             "log":["INFO  Selecting EF.DG1"]}
        """
    }
}
