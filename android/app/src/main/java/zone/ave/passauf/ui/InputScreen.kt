package zone.ave.passauf.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material.icons.filled.FolderOpen
import androidx.activity.compose.BackHandler
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CalendarMonth
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Card
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import zone.ave.passauf.AccessForm
import zone.ave.passauf.KeyKind
import zone.ave.passauf.PassaufNative
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

private val MRZ_DATE = DateTimeFormatter.ofPattern("yyMMdd").withZone(ZoneOffset.UTC)

/**
 * Where the user says what the document has printed on it.
 *
 * The MRZ fields are the same three BAC has always wanted, and the camera can fill
 * them in rather than have them typed. A CAN is quicker to type but only works on a
 * document that offers PACE.
 */
@Composable
fun InputScreen(
    form: AccessForm,
    onChange: ((AccessForm) -> AccessForm) -> Unit,
    onReady: () -> Unit,
    onScanned: (PassaufNative.ScannedMrz) -> Unit,
    onOpenSaved: (Uri) -> Unit,
    modifier: Modifier = Modifier,
) {
    val openSaved = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { source -> source?.let(onOpenSaved) }
    // Local to this screen rather than a state in the ViewModel: scanning is a way of
    // filling the form in, not a step of reading a document, and the back stack should
    // treat it that way.
    var scanning by remember { mutableStateOf(false) }

    if (scanning) {
        BackHandler { scanning = false }
        ScanMrzScreen(
            // Straight on to the chip. The scanner does not report a zone until every
            // check digit in it has passed, so there is nothing left to confirm.
            onFound = { scanned ->
                scanning = false
                onScanned(scanned)
            },
            onCancel = { scanning = false },
            modifier = modifier,
        )
        return
    }

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            "What is printed on the document?",
            style = MaterialTheme.typography.titleLarge,
        )

        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            KeyKind.entries.forEachIndexed { index, kind ->
                SegmentedButton(
                    selected = form.kind == kind,
                    onClick = { onChange { it.copy(kind = kind) } },
                    shape = SegmentedButtonDefaults.itemShape(index, KeyKind.entries.size),
                ) {
                    Text(if (kind == KeyKind.MRZ) "Document number" else "CAN")
                }
            }
        }

        if (form.kind == KeyKind.MRZ) {
            OutlinedButton(
                onClick = { scanning = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.PhotoCamera, contentDescription = null)
                Spacer(Modifier.padding(horizontal = 4.dp))
                Text("Scan the printed rows")
            }
        }

        when (form.kind) {
            KeyKind.MRZ -> MrzFields(form, onChange)
            KeyKind.CAN -> CanField(form, onChange)
        }

        Card {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Read images", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "The portrait and other pictures. These are much larger than the rest, " +
                            "so leaving them out makes for a noticeably quicker read.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.padding(horizontal = 8.dp))
                Switch(
                    checked = form.readImages,
                    onCheckedChange = { checked -> onChange { it.copy(readImages = checked) } },
                )
            }
        }

        Button(
            onClick = onReady,
            enabled = form.isComplete,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Scan document")
        }

        OutlinedButton(
            onClick = { openSaved.launch(arrayOf("application/zip", "*/*")) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Filled.FolderOpen, contentDescription = null)
            Spacer(Modifier.padding(horizontal = 4.dp))
            Text("Open a saved read")
        }

        if (form.kind == KeyKind.CAN) {
            Text(
                "A CAN only works on documents that offer PACE. If the document is older, " +
                    "use the document number instead.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun MrzFields(form: AccessForm, onChange: ((AccessForm) -> AccessForm) -> Unit) {
    OutlinedTextField(
        value = form.documentNumber,
        onValueChange = { value -> onChange { it.copy(documentNumber = value.uppercase()) } },
        label = { Text("Document number") },
        supportingText = { Text("As printed, without the check digit") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.Characters,
            imeAction = ImeAction.Next,
        ),
        modifier = Modifier.fillMaxWidth(),
    )

    MrzDateField(
        label = "Date of birth",
        value = form.dateOfBirth,
        // Nobody alive was born after today, and a two-digit year would read a
        // future date as the 1900s anyway.
        allowFuture = false,
        onValueChange = { value -> onChange { it.copy(dateOfBirth = value) } },
    )

    MrzDateField(
        label = "Date of expiry",
        value = form.dateOfExpiry,
        allowFuture = true,
        onValueChange = { value -> onChange { it.copy(dateOfExpiry = value) } },
    )
}

@Composable
private fun CanField(form: AccessForm, onChange: ((AccessForm) -> AccessForm) -> Unit) {
    OutlinedTextField(
        value = form.cardAccessNumber,
        onValueChange = { value ->
            onChange { it.copy(cardAccessNumber = value.filter { char -> char.isDigit() }) }
        },
        label = { Text("Card Access Number") },
        supportingText = {
            Text(
                "Usually six digits. On the identity page, on the back of a card, or " +
                    "sometimes on the page after."
            )
        },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.NumberPassword,
            imeAction = ImeAction.Done,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
}

/**
 * A YYMMDD field, typed or picked.
 *
 * The chip wants exactly these six characters, so that is what is stored; the
 * picker is there because typing a date backwards is easy to get wrong.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MrzDateField(
    label: String,
    value: String,
    allowFuture: Boolean,
    onValueChange: (String) -> Unit,
) {
    var pickerOpen by remember { mutableStateOf(false) }

    OutlinedTextField(
        value = value,
        onValueChange = { typed -> onValueChange(typed.filter { it.isDigit() }.take(6)) },
        label = { Text(label) },
        supportingText = { Text("YYMMDD") },
        isError = value.isNotEmpty() && value.length != 6,
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.NumberPassword,
            imeAction = ImeAction.Next,
        ),
        trailingIcon = {
            IconButton(onClick = { pickerOpen = true }) {
                Icon(Icons.Default.CalendarMonth, contentDescription = "Pick $label")
            }
        },
        modifier = Modifier.fillMaxWidth(),
    )

    if (!pickerOpen) {
        return
    }

    val state = rememberDatePickerState(
        // A passport is valid for at most ten years or so, and nobody is over
        // 130, so this covers both fields without offering nonsense.
        yearRange = if (allowFuture) 1900..2100 else 1890..java.time.Year.now().value,
    )
    DatePickerDialog(
        onDismissRequest = { pickerOpen = false },
        confirmButton = {
            TextButton(
                onClick = {
                    state.selectedDateMillis?.let { millis ->
                        onValueChange(MRZ_DATE.format(Instant.ofEpochMilli(millis)))
                    }
                    pickerOpen = false
                },
            ) { Text("Use this date") }
        },
        dismissButton = {
            TextButton(onClick = { pickerOpen = false }) { Text("Cancel") }
        },
    ) {
        DatePicker(state = state, title = { Text("  $label", Modifier.padding(16.dp)) })
    }
}
