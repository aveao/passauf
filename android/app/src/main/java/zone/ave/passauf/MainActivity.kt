package zone.ave.passauf

import android.nfc.NfcAdapter
import android.os.Bundle
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
class MainActivity : ComponentActivity() {

    private val viewModel: ReaderViewModel by viewModels()
    private var nfcAdapter: NfcAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

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
        // Reader mode keeps the platform from firing its own tag intents at us,
        // which would otherwise restart the activity mid-read.
        nfcAdapter?.enableReaderMode(
            this,
            { tag -> viewModel.onTagDiscovered(tag) },
            // eMRTDs are ISO/IEC 14443 type A or B, and never have an NDEF
            // message to look for.
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            Bundle().apply {
                // A document sitting against the back of a phone answers slowly
                // enough that the default presence check can drop it mid-read.
                putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 5000)
            },
        )
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("passauf") },
                navigationIcon = {
                    // Only the screens that came from the form can go back to it.
                    if (state !is ReadState.Editing) {
                        IconButton(onClick = viewModel::backToForm) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "Back to the details",
                            )
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

        val modifier = Modifier
            .fillMaxSize()
            .padding(padding)

        if (!nfcEnabled) {
            NfcOffScreen(modifier)
            return@Scaffold
        }

        when (val current = state) {
            is ReadState.Editing -> InputScreen(
                form = form,
                onChange = viewModel::updateForm,
                onReady = viewModel::armScanner,
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
                filesOnDisk = current.filesOnDisk,
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
