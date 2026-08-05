package zone.ave.passauf

import android.app.Application
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.isActive
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
    /**
     * Records far more about the read, including the contents of every file.
     *
     * Deliberately not persisted anywhere: it lives in this form, so it is back off
     * again next time the app starts. Someone who turned it on to chase one problem
     * should not still be recording everything a month later.
     */
    val detailedLog: Boolean = false,
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

    data class Finished(
        val report: DocumentReport,
        val directory: File?,
        /** What this read was unlocked with, so a failure can name the right fields. */
        val keyKind: KeyKind,
        /** False once the read's files have been deleted, by us or by the user. */
        val filesOnDisk: Boolean = true,
    ) : ReadState
}

class ReaderViewModel(application: Application) : AndroidViewModel(application) {

    private val preferences = Preferences(application)

    private val _form = MutableStateFlow(AccessForm())
    val form: StateFlow<AccessForm> = _form.asStateFlow()

    private val _blockScreenshots = MutableStateFlow(preferences.blockScreenshots)
    val blockScreenshots: StateFlow<Boolean> = _blockScreenshots.asStateFlow()

    fun setBlockScreenshots(block: Boolean) {
        preferences.blockScreenshots = block
        _blockScreenshots.value = block
    }

    private val _state = MutableStateFlow<ReadState>(ReadState.Editing)
    val state: StateFlow<ReadState> = _state.asStateFlow()

    /**
     * The read currently in flight, if there is one.
     *
     * Kept because a read cannot simply be forgotten about. It holds the tag connection
     * open, it is sitting inside a blocking native call, and when it eventually returns
     * it will write its result over whatever the user has moved on to. Without a handle
     * on it there is no way to say "stop", and a read that has hung takes the app with
     * it until the process is restarted.
     */
    private var readJob: Job? = null

    init {
        // Anything still here belongs to a previous run of the app, which by
        // now has either been exported or is not wanted. A crash mid-read is
        // the usual reason for finding something.
        sweepDocuments(keep = null)
    }

    fun updateForm(update: (AccessForm) -> AccessForm) {
        _form.update(update)
    }

    /** Move to the scanning screen, so a tap on the document starts a read. */
    fun armScanner() {
        if (_form.value.isComplete) {
            _state.value = ReadState.WaitingForTag
        }
    }

    /**
     * Take the fields off a scanned machine readable zone and go straight to the chip.
     *
     * No stop at the form on the way. The camera only reports a zone once every check
     * digit in it has passed, so there is nothing here for the user to check that has
     * not already been checked more thoroughly than they could; showing them the three
     * fields to confirm would be asking them to approve arithmetic.
     *
     * Filling the form and arming together rather than leaving the caller to do both:
     * the two have to happen in that order and with nothing in between, which is a rule
     * about this state machine and belongs next to it.
     */
    fun useScannedMrz(scanned: PassaufNative.ScannedMrz) {
        _form.update { form ->
            form.copy(
                kind = KeyKind.MRZ,
                documentNumber = scanned.documentNumber,
                dateOfBirth = scanned.dateOfBirth,
                dateOfExpiry = scanned.dateOfExpiry,
            )
        }
        armScanner()
    }

    fun backToForm() {
        abandonRead()
        _state.value = ReadState.Editing
    }

    /**
     * Give up on the read in flight, if any.
     *
     * Cancelling the coroutine is only half of it: the read is blocked inside a native
     * call that knows nothing about coroutines, and will stay there until the chip
     * answers or the timeout runs out — twenty seconds per exchange, and there are
     * hundreds. The other half is the transceiver, which starts returning nothing once
     * the job is no longer active, so the read unwinds at the next APDU instead.
     */
    private fun abandonRead() {
        readJob?.cancel()
        readJob = null
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
        // One at a time. A previous read still running owns the tag connection, and
        // starting a second would have two of them talking to one chip.
        if (readJob?.isActive == true) {
            Log.w(TAG, "A read is already running; ignoring this tag.")
            return
        }
        _state.value = ReadState.Reading("connecting", "Connecting to the document")

        readJob = viewModelScope.launch(Dispatchers.IO) {
            val form = _form.value
            val isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                _state.value = ReadState.Finished(
                    DocumentReport(
                        ok = false,
                        error = "That tag does not speak ISO-DEP, so it is not an eMRTD.",
                    ),
                    null,
                    form.kind,
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
                        logLevel = if (form.detailedLog) "debug" else "info",
                    ),
                    transceiver = { apdu ->
                        when {
                            // The only way out of a blocking native call: passauf treats
                            // nothing-back as a lost tag and unwinds, which it already
                            // knows how to do.
                            !isActive -> {
                                Log.i(TAG, "Read abandoned; answering no further APDUs.")
                                null
                            }
                            else -> try {
                                isoDep.transceive(apdu)
                            } catch (error: IOException) {
                                // The document moved. Returning null lets passauf
                                // unwind cleanly and report what it already has.
                                Log.w(TAG, "Lost the tag mid-exchange", error)
                                null
                            }
                        }
                    },
                    progress = { stage, message ->
                        _state.value = ReadState.Reading(stage, message)
                    },
                )
                // A read the user walked away from must not write itself over whatever
                // they are looking at now.
                if (isActive) {
                    _state.value = ReadState.Finished(report, directory, form.kind)
                }
            } catch (abandoned: CancellationException) {
                Log.i(TAG, "Read abandoned.")
                throw abandoned
            } catch (error: Throwable) {
                // Throwable, not Exception. An OutOfMemoryError or a link error is not
                // an Exception, and letting one past here leaves the state on Reading
                // for good: nothing else moves it, so every later tap is ignored and
                // only restarting the app helps. That is the failure this catch exists
                // for, far more than the ordinary ones.
                Log.e(TAG, "Read failed", error)
                _state.value = ReadState.Finished(
                    DocumentReport(
                        ok = false,
                        error = error.message ?: error.javaClass.simpleName,
                    ),
                    directory,
                    form.kind,
                )
            } finally {
                runCatching { isoDep.close() }
                Log.i(TAG, "Read finished, tag released.")
            }
        }
    }

    /**
     * Delete the files of the read currently on screen.
     *
     * A document's data groups hold the holder's name, date of birth and face.
     * The face is biometric data, so the less time it spends on disk the
     * better; this is for a user who has looked at a read and wants it gone
     * without waiting for the next one to clear it.
     */
    fun discardFiles() {
        val finished = _state.value as? ReadState.Finished ?: return
        sweepDocuments(keep = null)
        _state.value = finished.copy(filesOnDisk = false)
    }

    /**
     * A fresh directory for this read's files.
     *
     * Under the cache rather than the app's data directory: these files are
     * disposable, the system may reclaim them under storage pressure, and they
     * are never backed up or carried to a new device. Each read gets its own
     * directory, and taking a new one deletes the last, so at most one
     * document's files are ever on disk.
     */
    private fun documentDirectory(form: AccessForm): File {
        val root = File(getApplication<Application>().cacheDir, "documents")
        val directory = File(root, "${System.currentTimeMillis()}-${form.dumpName()}")
        sweepDocuments(keep = directory)
        directory.mkdirs()
        return directory
    }

    /**
     * Delete every read's files except, optionally, one.
     *
     * Deliberately not called when the user merely navigates back: a share
     * hands the receiving app a content URI it may not have finished reading,
     * and pulling the file out from under it would fail the export the user
     * just asked for. Clearing on the next read and on the next start bounds
     * this to one document, and [discardFiles] is there for right now.
     */
    private fun sweepDocuments(keep: File?) {
        val root = File(getApplication<Application>().cacheDir, "documents")
        val previous = root.listFiles() ?: return
        for (directory in previous) {
            if (directory == keep) {
                continue
            }
            if (!directory.deleteRecursively()) {
                Log.w(TAG, "Could not delete ${directory.name}")
            }
        }
    }
}
