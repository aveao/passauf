package io.github.aveao.passauf.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.aveao.passauf.Detail
import io.github.aveao.passauf.DocumentDetails
import io.github.aveao.passauf.DocumentReport
import io.github.aveao.passauf.FileReport
import io.github.aveao.passauf.Sharing
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
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val dumped = remember(report) {
        report.files.flatMap { it.dumped }.map(::File).filter { it.exists() }
    }

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (!report.ok) {
            item { FailureCard(report) }
        }

        report.document?.let { document ->
            item { IdentityCard(document, report.portraits.firstOrNull()) }
            if (document.personalDetails.isNotEmpty()) {
                item { DetailsCard("Additional personal details", document.personalDetails) }
            }
            if (document.documentDetails.isNotEmpty()) {
                item { DetailsCard("Additional document details", document.documentDetails) }
            }
        }

        if (report.ok) {
            item { ValidationCard(report) }
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
                FileCard(file)
            }
        }

        item { LogCard(report.log) }

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
                if (report.log.isNotEmpty()) {
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
private fun FailureCard(report: DocumentReport) {
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
                "A wrong document number, date of birth or date of expiry is by far the most " +
                    "likely cause; the chip cannot tell you which one was wrong.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun IdentityCard(document: DocumentDetails, portraitPath: String?) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.Top) {
                Portrait(portraitPath)
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

@Composable
private fun Portrait(path: String?) {
    val bitmap = remember(path) {
        path?.let { runCatching { BitmapFactory.decodeFile(it) }.getOrNull() }
    }

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
            // Android decodes JPEG but not JPEG 2000, which plenty of documents
            // use for DG2. The file is still saved, it just cannot be shown.
            path != null -> Text(
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
                    detail = authentication.algorithm
                        ?: "The document accepted the details you entered.",
                )
            }

            val chip = report.chipAuthentication
            when (chip?.status) {
                "passed" -> CheckRow(
                    icon = Icons.Default.CheckCircle,
                    tint = StatusColors.good,
                    title = "Chip Authentication passed",
                    detail = "The chip holds the private key for the key in " +
                        "${chip.source ?: "the document"}" +
                        (chip.curve?.let { ", on $it" } ?: "") +
                        ". This shows the chip was not cloned, not that the key is trusted.",
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
private fun FileCard(file: FileReport) {
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

            if (file.details.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                file.details.forEach { DetailRow(it.label, it.value, monospaceValue = true) }
            }

            val dumped = file.dumped.map(::File).filter { it.exists() }
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

/** ISO dates from the library, shown the way the phone's locale writes them. */
private fun formatDate(isoDate: String?): String? {
    if (isoDate.isNullOrBlank()) {
        return null
    }
    return runCatching { LocalDate.parse(isoDate).format(LOCAL_DATE) }.getOrDefault(isoDate)
}
