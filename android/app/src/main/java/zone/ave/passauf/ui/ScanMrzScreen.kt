package zone.ave.passauf.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Matrix
import android.util.Log
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
import androidx.compose.foundation.layout.aspectRatio
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
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
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
import zone.ave.passauf.MrzRecognizer
import zone.ave.passauf.PassaufNative
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/**
 * The two shapes a machine readable zone comes in, as far as aiming at one goes.
 *
 * A passport carries two rows of forty four characters, so its zone is a long thin
 * band; an identity card three rows of thirty, which is shorter and squarer. The
 * numbers err generous in both cases, because the guide only has to *contain* the
 * zone, and a box with room to spare is far easier to aim than a tight one.
 */
enum class DocumentShape(val label: String, val aspect: Float) {
    Passport("Passport", 9f),
    Card("ID / licence", 5f),
}

/** How much of the frame's width the guide takes up. */
private const val GUIDE_WIDTH_FRACTION = 0.92f

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
 * The library decides what is really a candidate, and it normalises before measuring.
 * This is here so the overlay can point at the row that nearly worked.
 */
private val CANDIDATE_LINE_LENGTHS = setOf(30, 36, 44)

/**
 * What the recogniser is seeing right now.
 *
 * A scan that never lands fails in one of a few ways, and they want different fixes,
 * so the numbers that tell them apart are worth showing: the frame size says whether
 * the camera gave us the resolution we asked for, the analysed size says whether the
 * crop is landing, and [problem] is the library saying how far the rows got.
 */
data class ScanDiagnostics(
    val frameWidth: Int,
    val frameHeight: Int,
    val analyzedWidth: Int,
    val analyzedHeight: Int,
    val framesSeen: Int,
    val recognizeMillis: Long,
    val lines: List<String>,
    val problem: String?,
)

/**
 * Reads the machine readable zone off a document with the camera.
 *
 * Only what falls inside the guide is recognised, which keeps the rest of the page out
 * of it, and everything that comes back goes to the passauf library to decide whether
 * it holds together. Nothing is reported until every check digit passes, so this either
 * hands back fields that are right or keeps looking; there is no state where it offers
 * a guess.
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
        CameraRefused(
            refused = refused,
            onRetry = { request.launch(Manifest.permission.CAMERA) },
            onCancel = onCancel,
            modifier = modifier,
        )
        return
    }

    // Written from the analyser's thread, which snapshot state allows, and read back on
    // the main thread by the effect below. That hop keeps the callback off a camera worker.
    var found by remember { mutableStateOf<PassaufNative.ScannedMrz?>(null) }
    LaunchedEffect(found) {
        found?.let(onFound)
    }

    var shape by remember { mutableStateOf(DocumentShape.Passport) }
    val currentShape by rememberUpdatedState(shape)

    // Off by default: this puts what is printed on the document on the screen, which is
    // wanted while working out why a scan will not land and not otherwise.
    var showDiagnostics by remember { mutableStateOf(false) }
    var diagnostics by remember { mutableStateOf<ScanDiagnostics?>(null) }

    // The guide has to sit over the frame the recogniser is given, not over the screen,
    // or the box on screen would be pointing somewhere the crop is not looking. Holding
    // the preview to the frame's own proportions is what keeps the two honest.
    val frameAspect = diagnostics
        ?.let { it.frameWidth.toFloat() / it.frameHeight.toFloat() }
        ?: (9f / 16f)

    Box(modifier = modifier.fillMaxSize().background(Color.Black)) {
        Box(
            modifier = Modifier
                .align(Alignment.Center)
                // fillMaxSize first so the ratio is fitted inside the screen rather than
                // driven off the bottom of it on a tall device.
                .fillMaxSize()
                .aspectRatio(frameAspect)
        ) {
            Viewfinder(
                shape = { currentShape },
                onFound = { scanned -> if (found == null) found = scanned },
                onDiagnostics = { latest -> diagnostics = latest },
                modifier = Modifier.fillMaxSize(),
            )
            GuideOverlay(shape = shape, modifier = Modifier.fillMaxSize())
        }

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
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                DocumentShape.entries.forEachIndexed { index, entry ->
                    SegmentedButton(
                        selected = shape == entry,
                        onClick = { shape = entry },
                        shape = SegmentedButtonDefaults.itemShape(
                            index,
                            DocumentShape.entries.size,
                        ),
                    ) {
                        Text(entry.label)
                    }
                }
            }
            Text(
                "Fill the box with the rows of letters and chevrons at the bottom of the " +
                    "document. Only what is inside it is read.",
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
 * The numbers stay put and the rows scroll, because there are usually more rows than
 * fit and the ones worth seeing are the last of them: a machine readable zone is at
 * the bottom of a document, so it is at the bottom of the reading order too.
 */
@Composable
private fun DiagnosticsOverlay(
    diagnostics: ScanDiagnostics?,
    modifier: Modifier = Modifier,
) {
    val rows = rememberScrollState()

    // maxValue only settles once the rows have been laid out, so this waits for it as
    // well as for the rows themselves.
    LaunchedEffect(diagnostics?.lines, rows.maxValue) {
        rows.scrollTo(rows.maxValue)
    }

    Column(
        modifier = modifier
            .fillMaxWidth(0.94f)
            .background(Color.Black.copy(alpha = 0.75f))
            .padding(8.dp),
    ) {
        if (diagnostics == null) {
            Mono("Waiting for the first frame.", Color.White)
            return@Column
        }

        Mono(
            "frame ${diagnostics.frameWidth}x${diagnostics.frameHeight}  " +
                "read ${diagnostics.analyzedWidth}x${diagnostics.analyzedHeight}",
            Color.Cyan,
        )
        Mono(
            "#${diagnostics.framesSeen}  ${diagnostics.recognizeMillis}ms  " +
                "${diagnostics.lines.size} rows",
            Color.Cyan,
        )
        diagnostics.problem?.let { problem ->
            Mono(problem, Color.Yellow)
        }

        Column(
            modifier = Modifier
                .heightIn(max = 180.dp)
                .verticalScroll(rows),
        ) {
            Column(modifier = Modifier.horizontalScroll(rememberScrollState())) {
                diagnostics.lines.forEach { line ->
                    val candidate = line.length in CANDIDATE_LINE_LENGTHS
                    Mono(
                        "%3d %s".format(line.length, line),
                        if (candidate) Color.Green else Color.White.copy(alpha = 0.7f),
                    )
                }
            }
        }
    }
}

@Composable
private fun Mono(text: String, color: Color) {
    Text(
        text = text,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        softWrap = false,
    )
}

/** The camera preview, with recognition running over the frames behind it. */
@Composable
private fun Viewfinder(
    shape: () -> DocumentShape,
    onFound: (PassaufNative.ScannedMrz) -> Unit,
    onDiagnostics: (ScanDiagnostics) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember {
        PreviewView(context).apply {
            // The whole frame has to be visible, because the guide drawn over this is
            // also what gets cropped out of it. Filling the view instead would show a
            // different picture from the one being read.
            scaleType = PreviewView.ScaleType.FIT_CENTER
        }
    }
    val executor = remember { Executors.newSingleThreadExecutor() }
    // Opened on the analyser's own thread, because Tesseract has to stay on one.
    val recognizer = remember { mutableStateOf<MrzRecognizer?>(null) }
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
            executor.execute { recognizer.value = MrzRecognizer.open(context) }
            analysis.setAnalyzer(
                executor,
                MrzAnalyzer(
                    recognizer = { recognizer.value },
                    shape = shape,
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
            // Released on the thread that opened it, then the thread is retired.
            executor.execute { recognizer.value?.close() }
            executor.shutdown()
        }
    }

    AndroidView(factory = { previewView }, modifier = modifier)
}

/** Dims everything outside the aiming guide and draws its outline. */
@Composable
private fun GuideOverlay(shape: DocumentShape, modifier: Modifier = Modifier) {
    Canvas(
        modifier = modifier.graphicsLayer {
            // Punching a hole with BlendMode.Clear needs somewhere to punch it.
            compositingStrategy = CompositingStrategy.Offscreen
        }
    ) {
        val width = size.width * GUIDE_WIDTH_FRACTION
        val height = width / shape.aspect
        val topLeft = Offset((size.width - width) / 2f, (size.height - height) / 2f)
        val guide = androidx.compose.ui.geometry.Size(width, height)

        drawRect(color = Color.Black.copy(alpha = 0.55f))
        drawRect(
            color = Color.Transparent,
            topLeft = topLeft,
            size = guide,
            blendMode = BlendMode.Clear,
        )
        drawRect(
            color = Color.White,
            topLeft = topLeft,
            size = guide,
            style = Stroke(width = 2.dp.toPx()),
        )
    }
}

/**
 * Crops each frame to the guide, hands that to the recogniser, and the result to the
 * library.
 *
 * Cropping is the point rather than an optimisation: a passport page is covered in text
 * a recogniser is happy to read, and every line of it is another chance for something
 * the wrong length to land between the two that matter.
 *
 * Deciding which rows are the machine readable zone belongs to the library, where the
 * CLI benefits from it too, and where it can be tested without a camera.
 */
private class MrzAnalyzer(
    private val recognizer: () -> MrzRecognizer?,
    private val shape: () -> DocumentShape,
    private val onFound: (PassaufNative.ScannedMrz) -> Unit,
    private val onDiagnostics: (ScanDiagnostics) -> Unit,
) : ImageAnalysis.Analyzer {

    /** Set once a zone has been read, so later frames stop reporting the same one. */
    @Volatile
    private var done = false

    private var framesSeen = 0

    // Reaching for the underlying frame is what the crop below wants, and CameraX marks
    // that access experimental rather than gating it behind opt-in.
    @ExperimentalGetImage
    override fun analyze(proxy: ImageProxy) {
        // Whatever happens below, the frame has to go back, or the camera stops handing
        // over new ones and the viewfinder quietly freezes.
        try {
            if (proxy.image == null || done) {
                return
            }
            // Null while the model is still being unpacked, which takes a moment on
            // first run. Dropping these frames is the whole handling required.
            val engine = recognizer() ?: return

            framesSeen += 1
            val startedAt = System.nanoTime()
            val rotation = proxy.imageInfo.rotationDegrees
            val turned = rotation == 90 || rotation == 270
            val displayWidth = if (turned) proxy.height else proxy.width
            val displayHeight = if (turned) proxy.width else proxy.height

            val guideWidth = displayWidth * GUIDE_WIDTH_FRACTION
            val guideHeight = guideWidth / shape().aspect

            // The guide sits in the middle, and a quarter turn keeps a centred rectangle
            // centred, so putting it back into the sensor's own orientation is only a
            // matter of swapping the sides over.
            val cropWidth = (if (turned) guideHeight else guideWidth)
                .roundToInt().coerceIn(1, proxy.width)
            val cropHeight = (if (turned) guideWidth else guideHeight)
                .roundToInt().coerceIn(1, proxy.height)

            val cropped = try {
                val whole = proxy.toBitmap()
                val piece = Bitmap.createBitmap(
                    whole,
                    (proxy.width - cropWidth) / 2,
                    (proxy.height - cropHeight) / 2,
                    cropWidth,
                    cropHeight,
                    // Turns it the right way up, so nothing downstream has to.
                    Matrix().apply { postRotate(rotation.toFloat()) },
                    true,
                )
                if (piece !== whole) {
                    whole.recycle()
                }
                piece
            } catch (error: Exception) {
                Log.e("passauf", "Could not crop the frame to the guide.", error)
                return
            }

            val lines = try {
                engine.recognize(cropped)
            } finally {
                cropped.recycle()
            }
            val result = PassaufNative.parseMrz(lines)

            onDiagnostics(
                ScanDiagnostics(
                    frameWidth = displayWidth,
                    frameHeight = displayHeight,
                    analyzedWidth = cropWidth,
                    analyzedHeight = cropHeight,
                    framesSeen = framesSeen,
                    recognizeMillis = (System.nanoTime() - startedAt) / 1_000_000,
                    lines = lines,
                    problem = result.problem,
                )
            )

            result.mrz?.let { scanned ->
                done = true
                onFound(scanned)
            }
        } finally {
            proxy.close()
        }
    }
}
