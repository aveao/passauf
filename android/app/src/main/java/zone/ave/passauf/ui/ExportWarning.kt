package zone.ave.passauf.ui

import android.content.Context
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.delay

/** How long the confirm button stays out of reach, in seconds. */
private const val COUNTDOWN = 3

private const val PREFERENCES = "passauf"
private const val HAS_EXPORTED = "hasExported"

/**
 * Whether the warning is still owed.
 *
 * Once per install, not once per read. A dialog that appears every time is one people
 * learn to dismiss without reading, and a warning nobody reads is worse than none: it
 * costs the same and buys the illusion of having said something.
 */
fun oweExportWarning(context: Context): Boolean =
    !context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        .getBoolean(HAS_EXPORTED, false)

fun rememberExportWarningShown(context: Context) {
    context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(HAS_EXPORTED, true)
        .apply()
}

/**
 * Said once, before the first export of a document's contents.
 *
 * The wording is careful about what it claims. Keeping your own document's data is not
 * unlawful anywhere we know of, and saying it is would be a lie that costs us the next
 * warning too — someone who catches us overstating once discounts everything after.
 * What is actually true is narrower: the rules differ by country, and holding someone
 * else's is a different matter from holding your own.
 *
 * The countdown exists because the confirm button is the one thing here anybody looks
 * at. Three seconds is enough to make reading the cheaper option and short enough not
 * to be an obstacle.
 */
@Composable
fun ExportWarning(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    var remaining by remember { mutableIntStateOf(COUNTDOWN) }

    LaunchedEffect(Unit) {
        while (remaining > 0) {
            delay(1000)
            remaining -= 1
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Before you save this") },
        text = {
            Text(
                "This file holds what was on the document: the photograph, the name, " +
                    "the dates, and the number. Together those are also what unlocks " +
                    "the chip it came from.\n\n" +
                    "Keeping your own is your business, though what you may do with it " +
                    "differs from country to country and is worth knowing where you " +
                    "are. Holding someone else's is a different question, and one you " +
                    "should have an answer to before you do it.\n\n" +
                    "Either way, this is not a file to send anyone.",
                style = MaterialTheme.typography.bodyMedium,
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = remaining == 0) {
                Text(
                    if (remaining > 0) {
                        "I understand, and I have permission ($remaining)"
                    } else {
                        "I understand, and I have permission"
                    }
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Go back") }
        },
    )
}
