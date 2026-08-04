package zone.ave.passauf.ui

import android.Manifest
import android.content.pm.PackageManager
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.TextRecognizer
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import zone.ave.passauf.PassaufNative
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * How wide the aiming guide is against its height.
 *
 * A passport's MRZ band is roughly nine times as wide as it is tall, an identity
 * card's nearer four, because it fits three shorter lines instead of two long
 * ones. This sits between them and errs tall: the guide only has to *contain* the
 * zone, and a box with room to spare is far easier to aim than a tight one.
 */
private const val GUIDE_ASPECT = 6f

/** How much of the width the guide takes up. */
private const val GUIDE_WIDTH_FRACTION = 0.9f

/**
 * The camera wants a frame with enough pixels across to resolve single characters.
 *
 * Forty four characters of a passport's lower line have to land on enough sensor to
 * tell an 8 from a B. ImageAnalysis defaults to something near 640x480, which spreads
 * those characters over about fourteen pixels each and makes any recogniser look
 * broken. Asking for 1080p is the difference between working and not.
 */
private val ANALYSIS_RESOLUTION = Size(1920, 1080)

/**
 * Line lengths worth a second look, echoed from the library for the debug view alone.
 *
 * [zone.ave.passauf.PassaufNative.parseMrz] decides what is really a candidate, and it
 * normalises before measuring. This is here so the overlay can point at the line that
 * nearly worked, which is the difference between a recogniser reading nothing and one
 * reading almost the right thing.
 */
private val CANDIDATE_LINE_LENGTHS = setOf(30, 36, 44)

/**
 * What the recogniser is seeing right now.
 *
 * A scan that never lands fails in one of a few ways, and they want different fixes:
 * no lines at all is focus or resolution, lines of the wrong length is framing, and
 * lines of the right length that still do not parse is character confusion, which the
 * check digits are catching exactly as intended.
 */
data class ScanDiagnostics(
    val frameWidth: Int,
    val frameHeight: Int,
    val framesSeen: Int,
    val recognizeMillis: Long,
    val lines: List<String>,
)

/**
 * Reads the machine readable zone off a document with the camera.
 *
 * Everything the recogniser sees goes to the passauf library, which decides which of
 * those lines are the zone and whether they hold together. Nothing is reported until
 * every check digit passes, so this either hands back fields that are right or keeps
 * looking; there is no state where it offers a guess.
 *
 * Frames are looked at and dropped. Nothing is recorded, and the app holds no INTERNET
 * permission, so nothing here can leave the device.
 *
 * @param onFound called once, with fields that have already been checked.
 * @param onCancel the user backing out, whether or not they granted the camera.
 */
@Composable
fun ScanMrzScreen(
    onFound: (PassaufNative.ScannedMrz) -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    var refused by remember { mutableStateOf(false) }

    val request = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { allowed ->
        granted = allowed
        refused = !allowed
    }

    LaunchedEffect(Unit) {
        if (!granted) {
            request.launch(Manifest.permission.CAMERA)
        }
    }

    if (!granted) {
        CameraRefused(refused = refused, onRetry = { request.launch(Manifest.permission.CAMERA) }, onCancel = onCancel, modifier = modifier)
        return
    }

    // Written from the analyser's thread, which snapshot state allows, and read back
    // on the main thread by the effect below. That hop is what keeps the callback
    // off a camera worker.
    var found by remember { mutableStateOf<PassaufNative.ScannedMrz?>(null) }
    LaunchedEffect(found) {
        found?.let(onFound)
    }

    // Off by default: this puts what is printed on the document on the screen, which is
    // wanted while working out why a scan will not land and not otherwise.
    var showDiagnostics by remember { mutableStateOf(false) }
    var diagnostics by remember { mutableStateOf<ScanDiagnostics?>(null) }

    Box(modifier = modifier.fillMaxSize()) {
        Viewfinder(
            onFound = { scanned -> if (found == null) found = scanned },
            onDiagnostics = { latest -> diagnostics = latest },
            modifier = Modifier.fillMaxSize(),
        )
        GuideOverlay(modifier = Modifier.fillMaxSize())

        IconButton(
            onClick = { showDiagnostics = !showDiagnostics },
            modifier = Modifier.align(Alignment.TopEnd).padding(8.dp),
        ) {
            Icon(
                Icons.Filled.BugReport,
                contentDescription = if (showDiagnostics) {
                    "Hide what the camera is reading"
                } else {
                    "Show what the camera is reading"
                },
                tint = if (showDiagnostics) Color.White else Color.White.copy(alpha = 0.5f),
            )
        }

        if (showDiagnostics) {
            DiagnosticsOverlay(
                diagnostics = diagnostics,
                modifier = Modifier.align(Alignment.TopStart).padding(8.dp),
            )
        }

        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                "Line up the rows of letters and chevrons at the bottom of the document.",
                style = MaterialTheme.typography.bodyMedium,
                color = Color.White,
                textAlign = TextAlign.Center,
            )
            TextButton(onClick = onCancel) {
                Text("Type it in instead", color = Color.White)
            }
        }
    }
}

@Composable
private fun CameraRefused(
    refused: Boolean,
    onRetry: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            if (refused) "No camera, no scanning" else "The camera is for reading the document",
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
        )
        Text(
            "The camera only reads the rows of letters printed at the bottom of the document, " +
                "so they do not have to be typed. Frames are looked at and thrown away, and " +
                "nothing is stored or sent anywhere.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        if (refused) {
            Button(onClick = onRetry) { Text("Ask again") }
        }
        TextButton(onClick = onCancel) { Text("Type it in instead") }
    }
}

/**
 * Everything the recogniser returned from the last frame that held any text.
 *
 * Each line carries its length, because that is the fastest way to tell which kind of
 * failure is happening: a 44 that will not parse is a misread character, a 43 is a
 * dropped one, and no lines at all means the camera never resolved the print.
 */
@Composable
private fun DiagnosticsOverlay(
    diagnostics: ScanDiagnostics?,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxWidth(0.92f)
            .heightIn(max = 260.dp)
            .background(Color.Black.copy(alpha = 0.75f))
            .padding(8.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        if (diagnostics == null) {
            Text(
                "Waiting for the first frame.",
                color = Color.White,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
            )
            return@Column
        }

        Text(
            "${diagnostics.frameWidth}x${diagnostics.frameHeight}  " +
                "frame ${diagnostics.framesSeen}  ${diagnostics.recognizeMillis}ms",
            color = Color.Cyan,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
        )

        if (diagnostics.lines.isEmpty()) {
            Text(
                "no text recognised",
                color = Color.Yellow,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
            )
            return@Column
        }

        Column(modifier = Modifier.horizontalScroll(rememberScrollState())) {
            diagnostics.lines.forEach { line ->
                val candidate = line.length in CANDIDATE_LINE_LENGTHS
                Text(
                    "%3d %s".format(line.length, line),
                    color = if (candidate) Color.Green else Color.White.copy(alpha = 0.7f),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    softWrap = false,
                )
            }
        }
    }
}

/** The camera preview, with recognition running over the frames behind it. */
@Composable
private fun Viewfinder(
    onFound: (PassaufNative.ScannedMrz) -> Unit,
    onDiagnostics: (ScanDiagnostics) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember { PreviewView(context) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val recognizer = remember { TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS) }
    val provider = remember { mutableStateOf<ProcessCameraProvider?>(null) }
    val currentOnFound by rememberUpdatedState(onFound)
    val currentOnDiagnostics by rememberUpdatedState(onDiagnostics)

    DisposableEffect(lifecycleOwner) {
        // The provider arrives whenever it arrives, which can be after this screen has
        // already gone away again, so binding is guarded rather than assumed.
        var gone = false
        val pending = ProcessCameraProvider.getInstance(context)
        pending.addListener({
            if (gone) {
                return@addListener
            }
            val cameraProvider = pending.get()
            provider.value = cameraProvider

            val preview = Preview.Builder().build()
            preview.surfaceProvider = previewView.surfaceProvider

            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(
                    ResolutionSelector.Builder()
                        .setAspectRatioStrategy(
                            AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
                        )
                        .setResolutionStrategy(
                            ResolutionStrategy(
                                ANALYSIS_RESOLUTION,
                                ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                            )
                        )
                        .build()
                )
                // A stale frame is worth nothing: queueing them would only widen the gap
                // between what the camera sees and what gets recognised.
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(
                executor,
                MrzAnalyzer(
                    recognizer = recognizer,
                    executor = executor,
                    onFound = { currentOnFound(it) },
                    onDiagnostics = { currentOnDiagnostics(it) },
                ),
            )

            cameraProvider.unbindAll()
            cameraProvider.bindToLifecycle(
                lifecycleOwner,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                analysis,
            )
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            gone = true
            provider.value?.unbindAll()
            recognizer.close()
            executor.shutdown()
        }
    }

    AndroidView(factory = { previewView }, modifier = modifier)
}

/** Dims everything outside the aiming guide and draws its outline. */
@Composable
private fun GuideOverlay(modifier: Modifier = Modifier) {
    Canvas(
        modifier = modifier.graphicsLayer {
            // Punching a hole with BlendMode.Clear needs somewhere to punch it.
            compositingStrategy = CompositingStrategy.Offscreen
        }
    ) {
        val width = size.width * GUIDE_WIDTH_FRACTION
        val height = width / GUIDE_ASPECT
        val topLeft = Offset((size.width - width) / 2f, (size.height - height) / 2f)
        val guide = androidx.compose.ui.geometry.Size(width, height)

        drawRect(color = Color.Black.copy(alpha = 0.55f))
        drawRect(color = Color.Transparent, topLeft = topLeft, size = guide, blendMode = BlendMode.Clear)
        drawRect(
            color = Color.White,
            topLeft = topLeft,
            size = guide,
            style = Stroke(width = 2.dp.toPx()),
        )
    }
}

/**
 * Hands each frame to the recogniser and the result to the library.
 *
 * Whatever text comes back goes over as it is. Deciding which lines are the machine
 * readable zone belongs to the library, where the CLI benefits from it too, and where
 * it can be tested without a camera.
 */
private class MrzAnalyzer(
    private val recognizer: TextRecognizer,
    private val executor: Executor,
    private val onFound: (PassaufNative.ScannedMrz) -> Unit,
    private val onDiagnostics: (ScanDiagnostics) -> Unit,
) : ImageAnalysis.Analyzer {

    /** Set once a zone has been read, so later frames stop reporting the same one. */
    @Volatile
    private var done = false

    private var framesSeen = 0

    // Reaching for the underlying frame is what ML Kit wants, and CameraX marks that
    // access experimental rather than gating it behind opt-in.
    @ExperimentalGetImage
    override fun analyze(proxy: ImageProxy) {
        val frame = proxy.image
        if (frame == null || done) {
            proxy.close()
            return
        }

        framesSeen += 1
        val startedAt = System.nanoTime()
        val width = proxy.width
        val height = proxy.height

        recognizer.process(InputImage.fromMediaImage(frame, proxy.imageInfo.rotationDegrees))
            .addOnSuccessListener(executor) { text ->
                if (done) {
                    return@addOnSuccessListener
                }
                val lines = text.textBlocks.flatMap { block -> block.lines }.map { it.text }

                onDiagnostics(
                    ScanDiagnostics(
                        frameWidth = width,
                        frameHeight = height,
                        framesSeen = framesSeen,
                        recognizeMillis = (System.nanoTime() - startedAt) / 1_000_000,
                        lines = lines,
                    )
                )

                PassaufNative.parseMrz(lines)?.let { scanned ->
                    done = true
                    onFound(scanned)
                }
            }
            // The frame has to be released whatever happened, or the camera stops
            // handing over new ones.
            .addOnCompleteListener(executor) { proxy.close() }
    }
}
