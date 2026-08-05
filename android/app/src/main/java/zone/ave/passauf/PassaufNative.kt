package zone.ave.passauf

import android.graphics.Bitmap
import android.util.Log
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * How both sides of the JNI boundary agree to spell things.
 *
 * Top level rather than inside [PassaufNative] so a test can use it without
 * loading the native library.
 */
internal val passaufJson = Json {
    ignoreUnknownKeys = true
    // A null is this side saying "you decide", and the Rust side reads an
    // absent field as its own default. Sending the null would say something
    // else.
    explicitNulls = false
    // Without this, kotlinx leaves out any property still equal to its declared
    // default, and Rust reads that absence as *its* default. That silently
    // turned readBinaryFiles = true into false, so the image data groups were
    // never read at all.
    encodeDefaults = true
}

/**
 * The passauf Rust library.
 *
 * There is one call: hand it what unlocks the document and something to talk to
 * the chip through, get back everything it read. The transport stays on this
 * side, because Android owns the NFC connection.
 */
object PassaufNative {

    private const val TAG = "passauf"

    init {
        System.loadLibrary("passauf")
    }

    /** Sends one command APDU to the chip and returns its response. */
    fun interface Transceiver {
        /**
         * @return the response APDU with its two status bytes, or null if the
         *   exchange failed. Returning null rather than throwing keeps the read
         *   from unwinding through the native frames.
         */
        fun transceive(apdu: ByteArray): ByteArray?
    }

    /** Called as the read moves along, from the thread doing the reading. */
    fun interface ProgressListener {
        /**
         * @param stage one of readingCardAccess, authenticating, authenticated,
         *   readingFile, checking, done.
         * @param message the same thing in words, ready to show.
         */
        fun onProgress(stage: String, message: String)
    }

    private external fun nativeReadDocument(
        optionsJson: String,
        transceiver: Transceiver,
        progress: ProgressListener?,
    ): String?

    private external fun nativeDecodeJpeg2000(data: ByteArray): IntArray?

    private external fun nativeParseMrz(text: String): String?

    private external fun nativeReadFiles(pathsJson: String): String?

    /**
     * Work out what a folder of data groups amounts to.
     *
     * For opening a read that was saved earlier. Files are matched to data groups by
     * name, and what comes back has no session in it, because there was none: how a chip
     * was authenticated when these were written says nothing about the files now.
     *
     * The hash check still runs and still means what it always did — the data groups
     * held against the EF.SOD beside them — because that is a property of the files
     * themselves.
     */
    fun readFiles(paths: List<String>): DocumentReport {
        val json = nativeReadFiles(passaufJson.encodeToString(paths))
            ?: return DocumentReport(ok = false, error = "The passauf library returned nothing.")
        return try {
            passaufJson.decodeFromString<DocumentReport>(json)
        } catch (error: Exception) {
            Log.e(TAG, "Could not read what passauf made of those files.", error)
            DocumentReport(ok = false, error = "Could not read what passauf returned.")
        }
    }

    /**
     * What a machine readable zone says, once one has been found.
     *
     * [documentCode] and [issuingState] name the document itself, which is how a
     * scan can tell what is about to be read before its chip has been touched. The
     * other three are what unlock it.
     */
    @Serializable
    data class ScannedMrz(
        val documentCode: String,
        val issuingState: String,
        val documentNumber: String,
        val dateOfBirth: String,
        val dateOfExpiry: String,
    )

    /**
     * A frame's worth of recognised text, and what became of it.
     *
     * Exactly one of these is set. [problem] says how far the lines got before
     * something refused them, which is the difference between a camera that cannot
     * resolve the print and one that is a single character away.
     */
    @Serializable
    data class MrzScanResult(
        val mrz: ScannedMrz? = null,
        val problem: String? = null,
    )

    /**
     * Find a machine readable zone in text recognised from an image.
     *
     * Hand over every line the recogniser produced, in reading order, and the
     * library sorts out which of them are the MRZ: lines are normalised, kept only
     * if they hold MRZ characters and are as long as some layout expects, and then
     * parsed and checked. Fields come back only once every check digit passes, so
     * what is returned can be trusted.
     *
     * Cheap enough to call per frame, and touches no card.
     */
    fun parseMrz(lines: List<String>): MrzScanResult {
        val json = nativeParseMrz(lines.joinToString("\n"))
            ?: return MrzScanResult(problem = "The passauf library returned nothing at all.")
        return try {
            passaufJson.decodeFromString<MrzScanResult>(json)
        } catch (error: Exception) {
            Log.e(TAG, "Could not read the parsed MRZ: $json", error)
            MrzScanResult(problem = "Could not read what passauf returned.")
        }
    }

    /**
     * Decode a JPEG 2000 image, which Android cannot do on its own.
     *
     * A good many issuers encode the face in DG2 as JPEG 2000, and
     * BitmapFactory has no decoder for it, so this borrows the one in the
     * passauf library. Try BitmapFactory first: it is hardware-accelerated and
     * handles the JPEG case, which is the other half of the documents.
     *
     * @return the image, or null if it is not JPEG 2000 or will not decode.
     */
    fun decodeJpeg2000(data: ByteArray): Bitmap? {
        // [width, height, then one packed ARGB_8888 pixel each].
        val decoded = nativeDecodeJpeg2000(data) ?: return null
        if (decoded.size < 2) {
            return null
        }
        val width = decoded[0]
        val height = decoded[1]
        if (width <= 0 || height <= 0 || decoded.size - 2 != width * height) {
            Log.e(TAG, "The decoded image does not describe $width x $height pixels.")
            return null
        }

        return Bitmap.createBitmap(
            decoded.copyOfRange(2, decoded.size),
            width,
            height,
            Bitmap.Config.ARGB_8888,
        )
    }

    /**
     * Read a document. Blocking, and long enough (seconds) that it must not run
     * on the main thread.
     */
    fun readDocument(
        options: ReadOptions,
        transceiver: Transceiver,
        progress: ProgressListener? = null,
    ): DocumentReport {
        val reportJson = nativeReadDocument(passaufJson.encodeToString(options), transceiver, progress)
            ?: return DocumentReport(
                ok = false,
                error = "The passauf library returned nothing at all.",
            )

        return try {
            passaufJson.decodeFromString<DocumentReport>(reportJson)
        } catch (error: Exception) {
            // A report we cannot read is still worth surfacing, since the raw
            // JSON usually says what went wrong.
            DocumentReport(
                ok = false,
                error = "Could not read the report passauf returned: ${error.message}",
                log = listOf(reportJson),
            )
        }
    }
}

@Serializable
data class ReadOptions(
    val accessKey: AccessKey,
    /** Read DG2 and friends too. They hold the images, and are much larger. */
    val readBinaryFiles: Boolean = true,
    /** Directory to write the document's files into. Must already exist. */
    val dumpPath: String? = null,
    val filePrefix: String? = null,
    /**
     * One of info, debug, warn, error, off.
     *
     * `trace` is not on that list and asking for it yields info: that level prints
     * session keys, the MRZ-derived seed and the decrypted contents of every file, and
     * a log this app holds can be handed to a share sheet. The Rust side refuses it
     * rather than trusting this side to not ask.
     */
    val logLevel: String = "info",
)

@Serializable
sealed interface AccessKey {
    /** The three fields from the machine readable zone. Works with BAC and PACE. */
    @Serializable
    @SerialName("mrz")
    data class Mrz(
        val documentNumber: String,
        /** YYMMDD */
        val dateOfBirth: String,
        /** YYMMDD */
        val dateOfExpiry: String,
    ) : AccessKey

    /** The Card Access Number printed on the document. PACE only. */
    @Serializable
    @SerialName("can")
    data class Can(val value: String) : AccessKey
}

@Serializable
data class DocumentReport(
    val ok: Boolean = false,
    val error: String? = null,
    /**
     * A short, stable name for why a read failed: authentication, canNeedsPace,
     * paceUnavailable, noFileList. Absent when it failed some other way.
     *
     * The sentence in [error] is for reading. This is for deciding what to offer, and
     * the two answers differ: wrong details and a document that slipped both read as
     * "could not read it", but only one of them is worth trying again unchanged.
     */
    val errorKind: String? = null,
    val authentication: AuthenticationReport? = null,
    val chipAuthentication: ChipAuthenticationReport? = null,
    val integrity: IntegrityReport? = null,
    val document: DocumentDetails? = null,
    val files: List<FileReport> = emptyList(),
    /** Paths of the portraits that were extracted, best first. */
    val portraits: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val log: List<String> = emptyList(),
)

@Serializable
data class AuthenticationReport(
    /** "PACE" or "BAC". */
    val method: String,
    val algorithm: String? = null,
)

@Serializable
data class ChipAuthenticationReport(
    /** notAttempted, passed, failed or noKeyAvailable. */
    val status: String,
    val source: String? = null,
    val curve: String? = null,
)

@Serializable
data class IntegrityReport(
    val securityObjectRead: Boolean = false,
    val hashAlgorithm: String? = null,
    /**
     * Every data group read matched EF.SOD. Internal consistency only: EF.SOD's
     * own signature is not checked, so this does not say the document is
     * genuine. See the note in the app's validation card.
     */
    val consistent: Boolean = false,
    val checked: List<Long> = emptyList(),
    val mismatched: List<Long> = emptyList(),
    val unchecked: List<Long> = emptyList(),
    val missingFromEfCom: List<Long> = emptyList(),
)

@Serializable
data class DocumentDetails(
    val mrzFormat: String? = null,
    val mrzRaw: String? = null,
    val mrzChecksumsValid: Boolean? = null,
    val documentCode: String? = null,
    val documentType: String? = null,
    val documentNumber: String? = null,
    val issuingState: String? = null,
    val nationality: String? = null,
    val surname: String? = null,
    val givenNames: String? = null,
    /** The holder's name as EF.DG11 spells it out, when the document carries one. */
    val fullName: String? = null,
    val sex: String? = null,
    /** YYYY-MM-DD */
    val dateOfBirth: String? = null,
    /** YYYY-MM-DD */
    val dateOfExpiry: String? = null,
    val optionalData: String? = null,
    val personalDetails: List<Detail> = emptyList(),
    val documentDetails: List<Detail> = emptyList(),
) {
    /**
     * The name to put in front of someone, DG11's where the document has one.
     *
     * The MRZ is the abbreviated copy: it truncates a name that will not fit its rows
     * and cannot write anything outside its own character set, so a holder whose name
     * is long or is not spelled in A-Z reads wrong there. DG11 is where the issuer put
     * the name in full. Most documents have no DG11 at all, hence the fallback.
     */
    val displayName: String?
        get() = fullName?.ifBlank { null } ?: mrzName

    /** The holder's name as the machine readable zone spells it, given names first. */
    val mrzName: String?
        get() = listOfNotNull(givenNames, surname)
            .filter { it.isNotBlank() }
            .joinToString(" ")
            .ifBlank { null }
}

@Serializable
data class FileReport(
    val name: String,
    val description: String,
    val fileId: String,
    val present: Boolean,
    val size: Int,
    /**
     * notApplicable, noSecurityObject, notCovered, matches or mismatch.
     *
     * notApplicable is a file EF.SOD could never cover — it hashes the LDS1 data
     * groups and nothing else — as opposed to notCovered, which is a data group it
     * could have recorded a hash for and did not.
     */
    val hashStatus: String,
    val expectedHash: String? = null,
    val actualHash: String? = null,
    val dumped: List<String> = emptyList(),
    /** Of [dumped], the ones that are pictures the library pulled out. */
    val images: List<String> = emptyList(),
    val details: List<Detail> = emptyList(),
)

@Serializable
data class Detail(
    val label: String,
    val value: String,
)
