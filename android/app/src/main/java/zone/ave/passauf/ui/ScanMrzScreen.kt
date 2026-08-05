package zone.ave.passauf.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Matrix
import android.util.Log
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
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
import androidx.compose.material.icons.filled.FlashlightOff
import androidx.compose.material.icons.filled.FlashlightOn
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.core.graphics.createBitmap
import androidx.lifecycle.compose.LocalLifecycleOwner
import zone.ave.passauf.MrzRecognizer
import zone.ave.passauf.PassaufNative
import java.util.concurrent.Executors
import kotlin.math.exp
import kotlin.math.roundToInt

/**
 * The two shapes a machine readable zone comes in, as far as aiming at one goes.
 *
 * A passport carries two rows of forty four characters, so its zone is a long thin
 * band; an identity card three rows of thirty, which is shorter and squarer. The
 * numbers err generous in both cases, because the guide only has to *contain* the
 * zone, and a box with room to spare is far easier to aim than a tight one.
 */
enum class DocumentShape(
    val label: String,
    /** Width of the aiming box against its height. */
    val aspect: Float,
    /** Rows the zone is printed in, and characters in each. */
    val rows: Int,
    val columns: Int,
    /** Width of the whole document against its height. */
    val documentAspect: Float,
    /** How much of the document's width the zone spans. */
    val zoneWidthOfDocument: Float,
    /** Gap under the zone, as a share of the document's height. */
    val zoneBottomMargin: Float,
) {
    // A passport's data page is ID-3, 125 by 88mm, and its zone is two rows of 44
    // characters at the 2.54mm pitch ICAO specifies — 111.8mm of the 125.
    Passport("Passport", 9f, 2, 44, 125f / 88f, 111.8f / 125f, 0.06f),

    // A card is ID-1, 85.6 by 54mm, with three rows of 30: 76.2mm of the 85.6.
    Card("ID / licence", 5f, 3, 30, 85.6f / 54f, 76.2f / 85.6f, 0.08f),
}

/** How much of the frame's width is read, whatever the guide happens to show. */
private const val ANALYSIS_WIDTH_FRACTION = 0.975f

/**
 * How much of the read region the drawn box covers.
 *
 * Deliberately well under one. The box is something to aim at, not a promise about
 * where reading stops, so a zone that fills it sits comfortably inside what is
 * actually looked at, with document either side of it.
 *
 * That margin is the point rather than a tolerance for bad aim. A recogniser finds a
 * line, and the breaks between its characters, from the whitespace around the print;
 * a zone crammed edge to edge gives it none, and the first and last characters come
 * back wrong while everything between them reads perfectly.
 */
private const val GUIDE_FILL = 0.78f

/**
 * Blank space put around the crop before it is read, as a share of the crop's height.
 *
 * Tesseract reads characters that touch the edge of an image badly — it is looking for
 * the whitespace a line of print normally sits in, and at the border there is none. Our
 * training renders all have wide page margins, so the model has never once seen a glyph
 * flush against an edge; handing it one is asking about a case that was never taught.
 *
 * This is why the leftmost characters were the ones coming back wrong.
 */
private const val QUIET_BORDER = 0.25f

/** Any size; the ghost row is measured at it and then scaled to fit. */
private val GHOST_PROBE_SIZE = 64.sp

/**
 * How much of the box a ghost row spans.
 *
 * Under one, because a real zone read at this distance does not touch the sides of the
 * box either — [GUIDE_FILL] leaves it room, and the ghost should show where the print
 * actually lands rather than where the box ends.
 */
private const val GHOST_ROW_FILL = 0.94f

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

    // A document under glass or laminate is often easiest to read with the light on, and
    // hardest with it on at the wrong angle, so this is the user's call rather than ours.
    var camera by remember { mutableStateOf<Camera?>(null) }
    var torch by remember { mutableStateOf(false) }

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
                onCamera = { bound -> camera = bound },
                modifier = Modifier.fillMaxSize(),
            )
            GuideOverlay(shape = shape, modifier = Modifier.fillMaxSize())
        }

        if (camera?.cameraInfo?.hasFlashUnit() == true) {
            IconButton(
                onClick = {
                    torch = !torch
                    camera?.cameraControl?.enableTorch(torch)
                },
                modifier = Modifier.align(Alignment.TopStart).padding(8.dp),
            ) {
                Icon(
                    if (torch) Icons.Filled.FlashlightOn else Icons.Filled.FlashlightOff,
                    contentDescription = if (torch) "Turn the light off" else "Turn the light on",
                    tint = if (torch) Color.White else Color.White.copy(alpha = 0.5f),
                )
            }
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
                // Clear of the row of buttons above it rather than underneath them.
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(start = 8.dp, end = 8.dp, top = 56.dp),
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
    onCamera: (Camera?) -> Unit,
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
    val currentOnCamera by rememberUpdatedState(onCamera)

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
            currentOnCamera(
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            )
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            gone = true
            currentOnCamera(null)
            // Unbinding puts the light out with it, so there is nothing else to undo.
            provider.value?.unbindAll()
            // Released on the thread that opened it, then the thread is retired.
            executor.execute { recognizer.value?.close() }
            executor.shutdown()
        }
    }

    AndroidView(factory = { previewView }, modifier = modifier)
}

/**
 * Dims everything outside the aiming guide, and shows what is meant to go in it.
 *
 * An empty rectangle floating over a camera does not say what to do with it. So the box
 * is drawn with a rough outline of the document around it, in the document's own
 * proportions and with the box where the zone actually sits — near the bottom — and the
 * box itself holds a ghost of the rows that belong there, at the right count, the right
 * number of characters, and the size they end up when the document is the right distance
 * away. Lining a document up against it is then a matter of matching two pictures rather
 * than guessing what the rectangle wants.
 */
@Composable
private fun GuideOverlay(shape: DocumentShape, modifier: Modifier = Modifier) {
    val measurer = rememberTextMeasurer()
    val ghost = remember(shape) { "<".repeat(shape.columns) }

    Canvas(
        modifier = modifier.graphicsLayer {
            // Punching a hole with BlendMode.Clear needs somewhere to punch it.
            compositingStrategy = CompositingStrategy.Offscreen
        }
    ) {
        val width = size.width * ANALYSIS_WIDTH_FRACTION * GUIDE_FILL
        val height = (size.width * ANALYSIS_WIDTH_FRACTION / shape.aspect) * GUIDE_FILL
        val topLeft = Offset((size.width - width) / 2f, (size.height - height) / 2f)
        val guide = androidx.compose.ui.geometry.Size(width, height)

        drawRect(color = Color.Black.copy(alpha = 0.55f))

        // The document around it, to its own proportions. Taller than the frame for a
        // passport, which is fine and even honest: the page carries on past the edge.
        val documentWidth = width / shape.zoneWidthOfDocument
        val documentHeight = documentWidth / shape.documentAspect
        val documentBottom = topLeft.y + height + documentHeight * shape.zoneBottomMargin
        val documentTopLeft = Offset(
            (size.width - documentWidth) / 2f,
            documentBottom - documentHeight,
        )
        drawRoundRect(
            color = Color.White.copy(alpha = 0.35f),
            topLeft = documentTopLeft,
            size = androidx.compose.ui.geometry.Size(documentWidth, documentHeight),
            cornerRadius = CornerRadius(documentHeight * 0.04f),
            style = Stroke(
                width = 1.5.dp.toPx(),
                pathEffect = PathEffect.dashPathEffect(
                    floatArrayOf(12.dp.toPx(), 8.dp.toPx())
                ),
            ),
        )

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

        // A row of filler at the size the real thing lands at. Measured once at an
        // arbitrary size and scaled, because what matters is that the characters span
        // the box, not what point size that turns out to be.
        val probe = measurer.measure(
            ghost,
            TextStyle(fontFamily = FontFamily.Monospace, fontSize = GHOST_PROBE_SIZE),
        )
        if (probe.size.width <= 0) {
            return@Canvas
        }
        val style = TextStyle(
            fontFamily = FontFamily.Monospace,
            fontSize = GHOST_PROBE_SIZE * (width * GHOST_ROW_FILL / probe.size.width),
            color = Color.White.copy(alpha = 0.30f),
        )
        val laid = measurer.measure(ghost, style)
        val rowHeight = height / shape.rows
        for (row in 0 until shape.rows) {
            drawText(
                textMeasurer = measurer,
                text = ghost,
                topLeft = Offset(
                    topLeft.x + (width - laid.size.width) / 2f,
                    topLeft.y + rowHeight * row + (rowHeight - laid.size.height) / 2f,
                ),
                style = style,
            )
        }
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
/**
 * How hard the tone curve pushes light and dark apart. Tuned, not guessed.
 *
 * Measured against a rendered row shaded across its width, blurred and noised to stand
 * in for a photograph: untouched it lost its first five characters, and so did a plain
 * contrast stretch. At 8 the row read perfectly. At 12 the curve began eating the
 * difference between B and 8, which is the pair that matters most here.
 */
private const val CONTRAST_STRENGTH = 8.0

/** Share of pixels ignored at each end when deciding what counts as black and white. */
private const val CONTRAST_CLIP = 0.02

/**
 * Pushes the paper towards white and the print towards black.
 *
 * Two reasons this earns its keep. A photograph of a document is lit unevenly — one end
 * of the zone in shadow, the other catching the light — and it is always the shaded end
 * whose characters come back wrong. And the model has only ever seen pure black on pure
 * white, because text2image renders bilevel; a flat grey frame is a kind of picture it
 * was never shown.
 *
 * The ends are found by percentile rather than by the darkest and lightest pixels
 * present, so one speck of dust or one specular highlight cannot decide the range for
 * the whole strip.
 */
private fun sharpen(crop: Bitmap): Bitmap {
    val width = crop.width
    val height = crop.height
    val pixels = IntArray(width * height)
    crop.getPixels(pixels, 0, width, 0, 0, width, height)

    val histogram = IntArray(256)
    val grey = ByteArray(pixels.size)
    for (index in pixels.indices) {
        val pixel = pixels[index]
        // Integer luminance, the usual 0.299/0.587/0.114 scaled by 256.
        val value = (
            (pixel shr 16 and 0xFF) * 77 +
                (pixel shr 8 and 0xFF) * 151 +
                (pixel and 0xFF) * 28
            ) shr 8
        grey[index] = value.toByte()
        histogram[value]++
    }

    val clip = (pixels.size * CONTRAST_CLIP).toInt()
    var low = 0
    var counted = 0
    while (low < 255 && counted + histogram[low] < clip) {
        counted += histogram[low]
        low++
    }
    var high = 255
    counted = 0
    while (high > low + 1 && counted + histogram[high] < clip) {
        counted += histogram[high]
        high--
    }

    // One value per input level, so the arithmetic happens 256 times rather than once
    // per pixel.
    val span = (high - low).coerceAtLeast(1).toDouble()
    fun sigmoid(level: Double) = 1.0 / (1.0 + exp(CONTRAST_STRENGTH * (0.5 - level)))
    val floor = sigmoid(0.0)
    val ceiling = sigmoid(1.0)
    val curve = IntArray(256) { level ->
        val stretched = ((level - low) / span).coerceIn(0.0, 1.0)
        (((sigmoid(stretched) - floor) / (ceiling - floor)) * 255.0)
            .roundToInt().coerceIn(0, 255)
    }

    for (index in pixels.indices) {
        val value = curve[grey[index].toInt() and 0xFF]
        pixels[index] = (0xFF shl 24) or (value shl 16) or (value shl 8) or value
    }

    val sharpened = createBitmap(width, height)
    sharpened.setPixels(pixels, 0, width, 0, 0, width, height)
    return sharpened
}

/**
 * Sets the crop in a margin of blank paper, which is where print normally sits.
 *
 * A recogniser looks for the whitespace around a line of text to find where the line
 * is and where each character starts. At the edge of an image there is none, so the
 * first and last characters of a row come back mangled while everything between them
 * reads perfectly. Every render the model trained on had wide page margins, so a glyph
 * flush against an edge is a case it was never shown.
 *
 * White rather than a sampled colour: an MRZ is dark print on a pale background, and
 * that is the contrast the model learned.
 */
private fun quiet(crop: Bitmap): Bitmap {
    val margin = (crop.height * QUIET_BORDER).roundToInt().coerceAtLeast(8)
    val padded = createBitmap(crop.width + margin * 2, crop.height + margin * 2)
    Canvas(padded).apply {
        drawColor(android.graphics.Color.WHITE)
        drawBitmap(crop, margin.toFloat(), margin.toFloat(), null)
    }
    return padded
}

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

            // What gets read, which is a good deal larger than the box on screen. The
            // guide only says where to put the zone.
            val analysisWidth = displayWidth * ANALYSIS_WIDTH_FRACTION
            val analysisHeight = analysisWidth / shape().aspect

            // The region sits in the middle, and a quarter turn keeps a centred rectangle
            // centred, so putting it back into the sensor's own orientation is only a
            // matter of swapping the sides over.
            val cropWidth = (if (turned) analysisHeight else analysisWidth)
                .roundToInt().coerceIn(1, proxy.width)
            val cropHeight = (if (turned) analysisWidth else analysisHeight)
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

            // Contrast first, then the border: a white margin added beforehand would sit
            // in the histogram and drag the idea of what counts as paper towards itself.
            val sharpened = sharpen(cropped)
            cropped.recycle()
            val padded = quiet(sharpened)
            sharpened.recycle()

            val lines = try {
                engine.recognize(padded)
            } finally {
                padded.recycle()
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
