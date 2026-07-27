package io.github.aveao.passauf

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The passauf Rust library.
 *
 * There is one call: hand it what unlocks the document and something to talk to
 * the chip through, get back everything it read. The transport stays on this
 * side, because Android owns the NFC connection.
 */
object PassaufNative {

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

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
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
        val reportJson = nativeReadDocument(json.encodeToString(options), transceiver, progress)
            ?: return DocumentReport(
                ok = false,
                error = "The passauf library returned nothing at all.",
            )

        return try {
            json.decodeFromString<DocumentReport>(reportJson)
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
    val logLevel: String = "debug",
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
    val sex: String? = null,
    /** YYYY-MM-DD */
    val dateOfBirth: String? = null,
    /** YYYY-MM-DD */
    val dateOfExpiry: String? = null,
    val optionalData: String? = null,
    val personalDetails: List<Detail> = emptyList(),
    val documentDetails: List<Detail> = emptyList(),
) {
    val fullName: String?
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
    /** noSecurityObject, notCovered, matches or mismatch. */
    val hashStatus: String,
    val expectedHash: String? = null,
    val actualHash: String? = null,
    val dumped: List<String> = emptyList(),
    val details: List<Detail> = emptyList(),
)

@Serializable
data class Detail(
    val label: String,
    val value: String,
)
