package zone.ave.passauf.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.automirrored.filled.Help
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import zone.ave.passauf.Detail
import zone.ave.passauf.DocumentDetails
import zone.ave.passauf.DocumentReport
import zone.ave.passauf.FileReport
import zone.ave.passauf.KeyKind
import zone.ave.passauf.PassaufNative
import zone.ave.passauf.Sharing
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

private val LOCAL_DATE: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)

@Composable
fun ResultScreen(
    report: DocumentReport,
    directory: File?,
    keyKind: KeyKind,
    filesOnDisk: Boolean,
    onDone: () -> Unit,
    onRetry: () -> Unit,
    onDiscardFiles: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val dumped = remember(report, filesOnDisk) {
        if (!filesOnDisk) {
            emptyList()
        } else {
            report.files.flatMap { it.dumped }.map(::File).filter { it.exists() }
        }
    }

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (!report.ok) {
            item { FailureCard(report, keyKind, onRetry) }
        }

        report.document?.let { document ->
            item { IdentityCard(document, report.portraits, report) }
        }

        // How the document was read and what that establishes, before the
        // details it contained: it is the part a reader has to weigh.
        if (report.ok) {
            item { ValidationCard(report) }
        }

        report.document?.let { document ->
            if (document.personalDetails.isNotEmpty()) {
                item { DetailsCard("Additional personal details", document.personalDetails) }
            }
            if (document.documentDetails.isNotEmpty()) {
                item { DetailsCard("Additional document details", document.documentDetails) }
            }
        }

        if (report.warnings.isNotEmpty()) {
            item { WarningsCard(report.warnings) }
        }

        if (report.files.isNotEmpty()) {
            item {
                Text(
                    "Files",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            items(report.files.filter { it.present }, key = { it.name }) { file ->
                FileCard(file, filesOnDisk)
            }
        }

        item { LogCard(report.log) }

        item { StorageCard(filesOnDisk, dumped.size, onDiscardFiles) }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (dumped.isNotEmpty()) {
                    Button(
                        onClick = { Sharing.shareAll(context, dumped) },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Export ${dumped.size} files")
                    }
                }
                if (report.log.isNotEmpty() && filesOnDisk) {
                    OutlinedButton(
                        onClick = { Sharing.shareLog(context, directory, report.log) },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Export the log") }
                }
                OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                    Text("Read another document")
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
private fun FailureCard(report: DocumentReport, keyKind: KeyKind, onRetry: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Could not read the document", style = MaterialTheme.typography.titleMedium)
            Text(
                report.error ?: "No reason given.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                // Naming the wrong fields would send someone checking a CAN
                // they never entered.
                when (keyKind) {
                    KeyKind.MRZ ->
                        "A wrong document number, date of birth or date of expiry is the most " +
                            "likely cause, and the chip cannot tell you which of the three it " +
                            "was. It is also possible the connection was lost: a document that " +
                            "shifts out of range part way through looks the same from here."
                    KeyKind.CAN ->
                        "A wrong CAN is the most likely cause — it is the short number " +
                            "printed on the document, not the document number. It is also " +
                            "possible the connection was lost: a document that shifts out of " +
                            "range part way through looks the same from here."
                },
                style = MaterialTheme.typography.bodySmall,
            )
            Button(onClick = onRetry, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Retry as-is")
            }
            Text(
                "Keeps the details you entered. Hold the document flat against the back of the " +
                    "phone and keep it still.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun IdentityCard(
    document: DocumentDetails,
    portraits: List<String>,
    report: DocumentReport,
) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.Top) {
                Portrait(portraits)
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        document.fullName ?: "Unknown holder",
                        style = MaterialTheme.typography.titleLarge,
                    )
                    document.documentType?.let {
                        Text(it, style = MaterialTheme.typography.bodyMedium)
                    }
                    document.documentNumber?.let {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                    ExpiryChip(document.dateOfExpiry)
                }
            }

            HorizontalDivider(Modifier.padding(vertical = 12.dp))

            // How the chip was opened, at a glance. The checks card below says
            // what it means; this is so it can be read without scrolling.
            DetailRow("Read with", accessSummary(report))
            DetailRow("Chip Authentication", chipAuthenticationSummary(report))

            DetailRow("Nationality", document.nationality)
            DetailRow("Issuing state", document.issuingState)
            DetailRow("Date of birth", formatDate(document.dateOfBirth))
            DetailRow("Date of expiry", formatDate(document.dateOfExpiry))
            DetailRow("Sex", document.sex)
            DetailRow("Optional data", document.optionalData)
            DetailRow("MRZ format", document.mrzFormat)
            document.mrzChecksumsValid?.let { valid ->
                DetailRow(
                    "MRZ check digits",
                    if (valid) "All valid" else "Mismatches found",
                )
            }
        }
    }
}

/**
 * The holder's portrait, from the first image that decodes.
 *
 * DG2 comes first in the list because it is the one a border check would use,
 * DG5's printed portrait after it. Each is tried with BitmapFactory first,
 * which is hardware-accelerated and covers the JPEG half of documents, then
 * with passauf's own decoder, which covers the JPEG 2000 half that Android
 * has no support for.
 */
@Composable
private fun Portrait(paths: List<String>) {
    val bitmap = decodedImages(remember(paths) { paths.map(::File) }).firstOrNull()

    Box(
        modifier = Modifier
            .size(width = 96.dp, height = 124.dp)
            .background(
                MaterialTheme.colorScheme.surfaceVariant,
                RoundedCornerShape(8.dp),
            ),
        contentAlignment = Alignment.Center,
    ) {
        when {
            bitmap != null -> Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = "Portrait from the document",
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxWidth(),
            )
            // Neither decoder could make sense of any of them. They are all
            // still saved, so the file can be opened elsewhere.
            paths.isNotEmpty() -> Text(
                "Saved,\nbut not\ndisplayable",
                style = MaterialTheme.typography.labelSmall,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> Text(
                "No\nportrait",
                style = MaterialTheme.typography.labelSmall,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ExpiryChip(dateOfExpiry: String?) {
    val expired = remember(dateOfExpiry) {
        dateOfExpiry?.let {
            runCatching { LocalDate.parse(it).isBefore(LocalDate.now()) }.getOrNull()
        }
    } ?: return

    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(if (expired) "Expired" else "In date") },
        leadingIcon = {
            Icon(
                if (expired) Icons.Default.Warning else Icons.Default.CheckCircle,
                contentDescription = null,
                tint = if (expired) StatusColors.bad else StatusColors.good,
            )
        },
        modifier = Modifier.padding(top = 8.dp),
    )
}

/**
 * What the read established about the document, and what it did not.
 *
 * The distinction matters more here than anywhere else in the app: passauf
 * checks that the document agrees with itself, not that a country issued it.
 */
@Composable
private fun ValidationCard(report: DocumentReport) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Checks", style = MaterialTheme.typography.titleMedium)

            report.authentication?.let { authentication ->
                CheckRow(
                    icon = Icons.Default.CheckCircle,
                    tint = StatusColors.good,
                    title = "Authenticated with ${authentication.method}",
                    detail = authentication.algorithm?.let { "Using $it." }
                        ?: "Basic Access Control, the older scheme. The document offered nothing " +
                        "better, so the session key is derived from the MRZ alone.",
                )
            }

            val chip = report.chipAuthentication
            when (chip?.status) {
                "passed" -> CheckRow(
                    icon = Icons.Default.CheckCircle,
                    tint = StatusColors.good,
                    title = "Chip Authentication passed" +
                        (chip.curve?.let { " on $it" } ?: ""),
                    detail = "Run as part of ${report.authentication?.algorithm ?: "PACE"}. " +
                        "The chip holds the private key for the key it published in " +
                        "${chip.source ?: "the document"}, which shows it was not cloned. It " +
                        "does not show that key is trusted.",
                )
                "failed" -> CheckRow(
                    icon = Icons.Default.Cancel,
                    tint = StatusColors.bad,
                    title = "Chip Authentication failed",
                    detail = "No key the document published matches the chip's mapping key. " +
                        "The chip may not be genuine.",
                )
                "noKeyAvailable" -> CheckRow(
                    icon = Icons.AutoMirrored.Filled.Help,
                    tint = StatusColors.unknown,
                    title = "Chip Authentication incomplete",
                    detail = "The document offered no key to check the chip against.",
                )
                else -> CheckRow(
                    icon = Icons.AutoMirrored.Filled.Help,
                    tint = StatusColors.unknown,
                    title = "Chip Authentication not attempted",
                    detail = "This document does not offer PACE with Chip Authentication Mapping.",
                )
            }

            val integrity = report.integrity
            when {
                integrity == null || !integrity.securityObjectRead -> CheckRow(
                    icon = Icons.AutoMirrored.Filled.Help,
                    tint = StatusColors.unknown,
                    title = "Data groups unchecked",
                    detail = "EF.SOD could not be read, so there was nothing to check against.",
                )
                integrity.mismatched.isNotEmpty() -> CheckRow(
                    icon = Icons.Default.Cancel,
                    tint = StatusColors.bad,
                    title = "${integrity.mismatched.size} of ${integrity.checked.size} " +
                        "data groups do not match EF.SOD",
                    detail = "Altered, or read incorrectly: " +
                        integrity.mismatched.joinToString(", ") { "DG$it" },
                )
                integrity.checked.isEmpty() -> CheckRow(
                    icon = Icons.AutoMirrored.Filled.Help,
                    tint = StatusColors.unknown,
                    title = "No data group hashes were checked",
                    detail = "Nothing EF.SOD covers was read.",
                )
                else -> CheckRow(
                    icon = Icons.Default.CheckCircle,
                    tint = StatusColors.good,
                    title = "All ${integrity.checked.size} data groups match EF.SOD",
                    detail = "Hashed with ${integrity.hashAlgorithm ?: "the document's digest"}." +
                        if (integrity.unchecked.isEmpty()) {
                            ""
                        } else {
                            " Not read, so not checked: " +
                                integrity.unchecked.joinToString(", ") { "DG$it" } + "."
                        },
                )
            }

            HorizontalDivider()

            CheckRow(
                icon = Icons.Default.Warning,
                tint = StatusColors.unknown,
                title = "Not checked: is the document genuine?",
                detail = "EF.SOD's own signature is not verified against a country's signing " +
                    "certificate, so everything above shows the document is internally " +
                    "consistent, not that it was issued by anyone. Certificate chain " +
                    "validation is still to come.",
            )
        }
    }
}

@Composable
private fun CheckRow(icon: ImageVector, tint: Color, title: String, detail: String) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(icon, contentDescription = null, tint = tint)
        Spacer(Modifier.width(12.dp))
        Column {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun WarningsCard(warnings: List<String>) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Warnings", style = MaterialTheme.typography.titleMedium)
            warnings.forEach { warning ->
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = StatusColors.unknown,
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(warning, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/**
 * Where this read's files are, and how to be rid of them.
 *
 * A document's data groups carry the holder's name, date of birth and face,
 * and a face is biometric data. Somebody who has read a document and moved on
 * should not have to guess whether a copy is still sitting on the phone, so
 * the app says plainly what it kept and offers to delete it now.
 */
@Composable
private fun StorageCard(filesOnDisk: Boolean, fileCount: Int, onDiscard: () -> Unit) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Files on this phone", style = MaterialTheme.typography.titleMedium)

            if (!filesOnDisk) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = StatusColors.good,
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        "Deleted. What is still on screen is only held in memory, and goes " +
                            "when you leave.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                return@Column
            }

            Text(
                "$fileCount files are in this app's cache so you can export them. They are " +
                    "deleted when you read the next document or reopen the app, are never " +
                    "backed up, and never leave the phone unless you share them.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = onDiscard, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.DeleteForever, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Delete them now")
            }
        }
    }
}

@Composable
private fun DetailsCard(title: String, details: List<Detail>) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            details.forEach { DetailRow(it.label, it.value) }
        }
    }
}

@Composable
private fun FileCard(file: FileReport, filesOnDisk: Boolean) {
    val context = LocalContext.current
    val expanded = remember { mutableStateMapOf<String, Boolean>() }
    val isOpen = expanded[file.name] == true

    Card {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded[file.name] = !isOpen },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                HashIcon(file.hashStatus)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(file.name, style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "${file.description} · ${file.size} bytes · ${file.fileId}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Icon(
                    if (isOpen) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (isOpen) "Collapse" else "Expand",
                )
            }

            if (!isOpen) {
                return@Column
            }

            Spacer(Modifier.height(12.dp))
            Text(hashStatusText(file), style = MaterialTheme.typography.bodySmall)

            val dumped = if (!filesOnDisk) {
                emptyList()
            } else {
                file.dumped.map(::File).filter { it.exists() }
            }

            // Which of the dumped files are pictures is the library's call,
            // not something to infer from a file extension here: a face image
            // whose format the document failed to name is dumped as
            // .image_bin, and guessing by extension hid it.
            val images = remember(file, filesOnDisk) {
                if (!filesOnDisk) {
                    emptyList()
                } else {
                    file.images.map(::File).filter { it.exists() }
                }
            }
            if (images.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                ImageStrip(images)
            }

            if (file.details.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                file.details.forEach { DetailRow(it.label, it.value, monospaceValue = true) }
            }

            if (dumped.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                dumped.forEach { saved ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { Sharing.shareFile(context, saved) }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null)
                        Spacer(Modifier.width(12.dp))
                        Text(saved.name, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

/**
 * The pictures a data group held, side by side and big enough to look at.
 *
 * Tapping one shares it, the same as tapping its filename below.
 */
@Composable
private fun ImageStrip(files: List<File>) {
    val context = LocalContext.current
    val bitmaps = decodedImages(files)

    if (bitmaps.isEmpty()) {
        Text(
            // Which is what a JPEG 2000 that even our own decoder choked on
            // looks like. The file is still there to be exported.
            "The image could not be decoded, but it was saved.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }

    Row(
        modifier = Modifier.horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        bitmaps.forEachIndexed { index, bitmap ->
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = "Image ${index + 1} from this data group",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .height(220.dp)
                    // Keep the document's own proportions: a face image is
                    // portrait, a signature is a wide strip.
                    .aspectRatio(bitmap.width.toFloat() / bitmap.height.toFloat())
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .clickable {
                        files.getOrNull(index)?.let { Sharing.shareFile(context, it) }
                    },
            )
        }
    }
}

/**
 * Decode images off the main thread.
 *
 * A JPEG 2000 face image goes through a software decoder and takes long enough
 * that doing it during composition would stall the frame. The result arrives
 * when it arrives; until then the caller shows its own placeholder.
 */
@Composable
private fun decodedImages(files: List<File>): List<Bitmap> {
    val bitmaps by produceState(initialValue = emptyList(), files) {
        value = withContext(Dispatchers.IO) {
            files.mapNotNull { runCatching { decodeImage(it) }.getOrNull() }
        }
    }
    return bitmaps
}


@Composable
private fun HashIcon(status: String) {
    when (status) {
        "matches" -> Icon(
            Icons.Default.CheckCircle,
            contentDescription = "Matches EF.SOD",
            tint = StatusColors.good,
        )
        "mismatch" -> Icon(
            Icons.Default.Cancel,
            contentDescription = "Does not match EF.SOD",
            tint = StatusColors.bad,
        )
        else -> Icon(
            Icons.AutoMirrored.Filled.Help,
            contentDescription = "Not covered by EF.SOD",
            tint = StatusColors.unknown,
        )
    }
}

private fun hashStatusText(file: FileReport): String = when (file.hashStatus) {
    "matches" -> "Matches its hash in EF.SOD."
    "mismatch" -> "Does NOT match EF.SOD.\nExpected ${file.expectedHash}\nGot      ${file.actualHash}"
    "notCovered" -> "EF.SOD records no hash for this file, so nothing was checked."
    else -> "EF.SOD was not read, so nothing was checked."
}

@Composable
private fun LogCard(log: List<String>) {
    var open by remember { mutableStateOf(false) }
    if (log.isEmpty()) {
        return
    }

    Card {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { open = !open },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Log (${log.size} lines)",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                Icon(
                    if (open) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (open) "Collapse" else "Expand",
                )
            }
            if (open) {
                Spacer(Modifier.height(8.dp))
                Column(Modifier.horizontalScroll(rememberScrollState())) {
                    log.forEach { line ->
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String?, monospaceValue: Boolean = false) {
    if (value.isNullOrBlank()) {
        return
    }
    Row(Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.Top) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(140.dp),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (monospaceValue) FontFamily.Monospace else null,
            modifier = Modifier.weight(1f),
        )
    }
}

/**
 * Decode an image a document carried, whatever it was encoded as.
 *
 * BitmapFactory first, since it handles JPEG and is hardware-accelerated;
 * passauf's decoder second, for the JPEG 2000 that Android has no support for
 * and that a great many issuers use for DG2.
 */
private fun decodeImage(file: File): Bitmap? {
    if (!file.exists()) {
        return null
    }
    BitmapFactory.decodeFile(file.absolutePath)?.let { return it }
    return PassaufNative.decodeJpeg2000(file.readBytes())
}

/** The access mode in one line: the scheme, and for PACE the variant that ran. */
private fun accessSummary(report: DocumentReport): String {
    val authentication = report.authentication ?: return "Unknown"
    return listOfNotNull(authentication.method, authentication.algorithm).joinToString(" · ")
}

/** Whether Chip Authentication ran, and over what, in one line. */
private fun chipAuthenticationSummary(report: DocumentReport): String {
    val chip = report.chipAuthentication ?: return "Not attempted"
    return when (chip.status) {
        "passed" -> listOfNotNull(
            "Passed",
            chip.curve,
            chip.source?.let { "key from $it" },
        ).joinToString(" · ")
        "failed" -> "Failed — no published key matches the chip"
        "noKeyAvailable" -> "Ran, but the document published no key to check"
        else -> "Not offered by this document"
    }
}

/** ISO dates from the library, shown the way the phone's locale writes them. */
private fun formatDate(isoDate: String?): String? {
    if (isoDate.isNullOrBlank()) {
        return null
    }
    return runCatching { LocalDate.parse(isoDate).format(LOCAL_DATE) }.getOrDefault(isoDate)
}
