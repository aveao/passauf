package zone.ave.passauf

import android.nfc.NfcAdapter
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import zone.ave.passauf.ui.SettingsScreen
import zone.ave.passauf.ui.InputScreen
import zone.ave.passauf.ui.PassaufTheme
import zone.ave.passauf.ui.ReadingScreen
import zone.ave.passauf.ui.ResultScreen
import zone.ave.passauf.ui.WaitingScreen

/**
 * The whole app.
 *
 * Reader mode stays on while the activity is in front, and the view model
 * decides whether a tag that turns up is one we currently want.
 */
/** How far apart the platform checks that the document is still there. */
private const val PRESENCE_CHECK_DELAY = 5000

/** How long to leave discovery off for, so that turning it back on takes effect. */
private const val READER_RESTART_PAUSE = 300L

class MainActivity : ComponentActivity() {

    private val viewModel: ReaderViewModel by viewModels()
    private var nfcAdapter: NfcAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        // The app switcher takes a picture of whatever was last on screen, which for
        // this app is a passport, and keeps it until the task is dismissed. Nobody asked
        // for that one, so it goes where it can, regardless of the setting. Deliberate
        // screenshots are a separate question and stay the user's to answer.
        //
        // Only from Android 13. Before that the single thumbnail cannot be suppressed on
        // its own: FLAG_SECURE takes it away along with every screenshot, which is the
        // trade this app declines to make for people. Said plainly in Settings instead.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.blockScreenshots.collect { block ->
                    if (block) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                }
            }
        }

        // Every time the app starts waiting for a document, including a retry with the
        // same one still held against the phone.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                viewModel.state
                    .map { it is ReadState.WaitingForTag }
                    .distinctUntilChanged()
                    .collect { waiting -> if (waiting) restartReaderMode() }
            }
        }

        setContent {
            PassaufTheme {
                PassaufApp(
                    viewModel = viewModel,
                    nfcEnabled = nfcAdapter?.isEnabled == true,
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        startReaderMode()
    }

    /**
     * Start looking for a document.
     *
     * Reader mode keeps the platform from firing its own tag intents at us, which would
     * otherwise restart the activity mid-read.
     */
    private fun startReaderMode() {
        nfcAdapter?.enableReaderMode(
            this,
            { tag -> viewModel.onTagDiscovered(tag) },
            // eMRTDs are ISO/IEC 14443 type A or B, and never have an NDEF message to
            // look for.
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            Bundle().apply {
                // A document sitting against the back of a phone answers slowly enough
                // that the default presence check can drop it mid-read.
                putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY)
            },
        )
    }

    /**
     * Look again, for a document that never went away.
     *
     * A tag is handed over once, when it is discovered, and the platform will not offer
     * the same one twice. It stops counting a tag as present only when a presence check
     * fails, and this app asks for those five seconds apart so that a slow chip is not
     * dropped part way through a read.
     *
     * The two together mean that after one read, the document lying against the phone is
     * still "there" as far as the platform is concerned. Moving it does nothing, and
     * taking it away needs several seconds to register before putting it back counts as
     * a new arrival. Turning reader mode off and on starts discovery over, so a document
     * that never moved is found again immediately.
     */
    private suspend fun restartReaderMode() {
        nfcAdapter?.disableReaderMode(this)
        // Long enough for the controller to actually drop its discovery loop; without
        // it the enable can land before the disable has taken effect.
        delay(READER_RESTART_PAUSE)
        startReaderMode()
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PassaufApp(viewModel: ReaderViewModel, nfcEnabled: Boolean) {
    val state by viewModel.state.collectAsState()
    val form by viewModel.form.collectAsState()
    val blockScreenshots by viewModel.blockScreenshots.collectAsState()

    // Local rather than a ReadState: settings are somewhere you step aside to, not a
    // stage of reading a document, and the back stack should treat them that way.
    var settings by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (settings) "Settings" else "passauf") },
                navigationIcon = {
                    // Only the screens that came from the form can go back to it.
                    if (settings) {
                        IconButton(onClick = { settings = false }) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "Back",
                            )
                        }
                    } else if (state !is ReadState.Editing) {
                        IconButton(onClick = viewModel::backToForm) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "Back to the details",
                            )
                        }
                    }
                },
                actions = {
                    // Only from the form: opening settings mid-read would either
                    // interrupt it or pretend the change applied to it.
                    if (!settings && state is ReadState.Editing) {
                        IconButton(onClick = { settings = true }) {
                            Icon(Icons.Filled.Settings, contentDescription = "Settings")
                        }
                    }
                },
            )
        },
    ) { padding ->
        // Every screen but the form was reached from the form, so that is where
        // back goes. Without this the system handles it and closes the app,
        // which throws away a read the user is still looking at.
        BackHandler(enabled = state !is ReadState.Editing, onBack = viewModel::backToForm)
        BackHandler(enabled = settings) { settings = false }

        val modifier = Modifier
            .fillMaxSize()
            .padding(padding)

        if (settings) {
            SettingsScreen(
                blockScreenshots = blockScreenshots,
                onBlockScreenshotsChange = viewModel::setBlockScreenshots,
                detailedLog = form.detailedLog,
                onDetailedLogChange = { on -> viewModel.updateForm { it.copy(detailedLog = on) } },
                modifier = modifier,
            )
            return@Scaffold
        }

        if (!nfcEnabled) {
            NfcOffScreen(modifier)
            return@Scaffold
        }

        when (val current = state) {
            is ReadState.Editing -> InputScreen(
                form = form,
                onChange = viewModel::updateForm,
                onReady = viewModel::armScanner,
                onScanned = viewModel::useScannedMrz,
                onOpenSaved = viewModel::openSavedRead,
                modifier = modifier,
            )
            is ReadState.WaitingForTag -> WaitingScreen(
                onCancel = viewModel::backToForm,
                modifier = modifier,
            )
            is ReadState.Reading -> ReadingScreen(
                message = current.message,
                modifier = modifier,
            )
            is ReadState.Finished -> ResultScreen(
                report = current.report,
                directory = current.directory,
                keyKind = current.keyKind,
                tagLost = current.tagLost,
                imported = current.imported,
                filesOnDisk = current.filesOnDisk,
                detailedLog = form.detailedLog,
                onDone = viewModel::backToForm,
                // Straight back to waiting for a tag, with the details the user
                // already entered: a lost connection needs no re-typing.
                onRetry = viewModel::armScanner,
                onDiscardFiles = viewModel::discardFiles,
                modifier = modifier,
            )
        }
    }
}

@Composable
private fun NfcOffScreen(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text("NFC is off", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Reading a document needs NFC. Turn it on in your phone's settings and come back.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 12.dp),
        )
    }
}
