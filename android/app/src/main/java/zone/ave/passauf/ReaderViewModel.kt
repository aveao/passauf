package zone.ave.passauf

import android.app.Application
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.io.IOException

private const val TAG = "passauf"

/** Which of the two things printed on the document we are going to use. */
enum class KeyKind { MRZ, CAN }

/**
 * What the user typed in.
 *
 * Kept as text rather than dates because that is what the chip wants: the MRZ
 * fields are six characters, check digits and all, and reformatting them would
 * only invite mistakes.
 */
data class AccessForm(
    val kind: KeyKind = KeyKind.MRZ,
    val documentNumber: String = "",
    /** YYMMDD */
    val dateOfBirth: String = "",
    /** YYMMDD */
    val dateOfExpiry: String = "",
    val cardAccessNumber: String = "",
    val readImages: Boolean = true,
) {
    val isComplete: Boolean
        get() = when (kind) {
            KeyKind.MRZ ->
                documentNumber.isNotBlank() &&
                    dateOfBirth.length == 6 &&
                    dateOfExpiry.length == 6
            KeyKind.CAN -> cardAccessNumber.length >= 4
        }

    fun toAccessKey(): AccessKey = when (kind) {
        KeyKind.MRZ -> AccessKey.Mrz(
            documentNumber = documentNumber.trim().uppercase(),
            dateOfBirth = dateOfBirth,
            dateOfExpiry = dateOfExpiry,
        )
        KeyKind.CAN -> AccessKey.Can(cardAccessNumber.trim())
    }

    /** Something to name this document's dump directory after. */
    fun dumpName(): String = when (kind) {
        KeyKind.MRZ -> documentNumber.trim().uppercase().ifBlank { "document" }
        // A CAN is a shared secret rather than an identifier, so it does not go
        // anywhere near a filename.
        KeyKind.CAN -> "document"
    }.replace(Regex("[^A-Za-z0-9_-]"), "_")
}

sealed interface ReadState {
    /** Waiting for the user to fill the form in. */
    data object Editing : ReadState

    /** Form is filled in, waiting for a document to come into range. */
    data object WaitingForTag : ReadState

    data class Reading(val stage: String, val message: String) : ReadState

    data class Finished(val report: DocumentReport, val directory: File?) : ReadState
}

class ReaderViewModel(application: Application) : AndroidViewModel(application) {

    private val _form = MutableStateFlow(AccessForm())
    val form: StateFlow<AccessForm> = _form.asStateFlow()

    private val _state = MutableStateFlow<ReadState>(ReadState.Editing)
    val state: StateFlow<ReadState> = _state.asStateFlow()

    fun updateForm(update: (AccessForm) -> AccessForm) {
        _form.update(update)
    }

    /** Move to the scanning screen, so a tap on the document starts a read. */
    fun armScanner() {
        if (_form.value.isComplete) {
            _state.value = ReadState.WaitingForTag
        }
    }

    fun backToForm() {
        _state.value = ReadState.Editing
    }

    /** Whether a tag arriving now should be read. */
    fun wantsTag(): Boolean = _state.value is ReadState.WaitingForTag

    /**
     * Read a document that has just come into range.
     *
     * Called from NFC's own thread; the work moves onto the IO dispatcher so
     * the read cannot block anything the system needs back.
     */
    fun onTagDiscovered(tag: Tag) {
        if (!wantsTag()) {
            return
        }
        _state.value = ReadState.Reading("connecting", "Connecting to the document")

        viewModelScope.launch(Dispatchers.IO) {
            val form = _form.value
            val isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                _state.value = ReadState.Finished(
                    DocumentReport(
                        ok = false,
                        error = "That tag does not speak ISO-DEP, so it is not an eMRTD.",
                    ),
                    null,
                )
                return@launch
            }

            var directory: File? = null
            try {
                isoDep.connect()
                // Reading DG2 off a slow chip takes a while per APDU, and the
                // default timeout is short enough to give up part way through.
                isoDep.timeout = 20_000

                directory = documentDirectory(form)
                val report = PassaufNative.readDocument(
                    options = ReadOptions(
                        accessKey = form.toAccessKey(),
                        readBinaryFiles = form.readImages,
                        dumpPath = directory.absolutePath,
                        filePrefix = form.dumpName(),
                    ),
                    transceiver = { apdu ->
                        try {
                            isoDep.transceive(apdu)
                        } catch (error: IOException) {
                            // The document moved. Returning null lets passauf
                            // unwind cleanly and report what it already has.
                            Log.w(TAG, "Lost the tag mid-exchange", error)
                            null
                        }
                    },
                    progress = { stage, message ->
                        _state.value = ReadState.Reading(stage, message)
                    },
                )
                _state.value = ReadState.Finished(report, directory)
            } catch (error: Exception) {
                Log.e(TAG, "Read failed", error)
                _state.value = ReadState.Finished(
                    DocumentReport(
                        ok = false,
                        error = error.message ?: error.javaClass.simpleName,
                    ),
                    directory,
                )
            } finally {
                runCatching { isoDep.close() }
            }
        }
    }

    /**
     * A fresh directory for this read's files, inside the app's own storage.
     *
     * Each read gets its own so a second attempt cannot leave half of an
     * earlier document's files mixed in with this one's.
     */
    private fun documentDirectory(form: AccessForm): File {
        val root = File(getApplication<Application>().filesDir, "documents")
        val directory = File(root, "${System.currentTimeMillis()}-${form.dumpName()}")
        directory.mkdirs()
        return directory
    }
}
