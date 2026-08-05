package zone.ave.passauf.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.util.Log

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import zone.ave.passauf.BuildConfig

/** Where this came from. */
private const val SOURCE = "https://github.com/aveao/passauf"

/**
 * The few things worth choosing, and why each one is worth choosing rather than being
 * decided here.
 *
 * The explanations are longer than a settings screen usually carries. That is on
 * purpose: both of these trade one real thing against another, and a switch with a
 * three-word label would be asking people to guess which.
 */
@Composable
fun SettingsScreen(
    blockScreenshots: Boolean,
    onBlockScreenshotsChange: (Boolean) -> Unit,
    detailedLog: Boolean,
    onDetailedLogChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SettingCard(
            title = "Block screenshots",
            explanation = "Stops the screen being captured or recorded while a document " +
                "is showing, and keeps it out of the app switcher.\n\n" +
                "Off by default. Nothing stops anyone photographing the printed page. " +
                "Worth turning on if you are sharing your screen, if your phone sends " +
                "screenshots somewhere, or if the document is not yours.",
            checked = blockScreenshots,
            onChange = onBlockScreenshotsChange,
        )

        SettingCard(
            title = "Detailed log",
            explanation = "Records what the document contained, file by file, so a read " +
                "that goes wrong can be worked out afterwards.\n\n" +
                "Turn it on only for that, and do not send the result to anyone. Off " +
                "again next time the app starts, so it cannot be left on and forgotten.",
            checked = detailedLog,
            onChange = onDetailedLogChange,
        )

        Text(
            recentsNote(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        SourceLink()

        // Which build this is, so a report of something going wrong can name it. The
        // code is here as well as the name because it is what an install is compared
        // by, and two builds can carry the same name.
        Text(
            "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.fillMaxWidth(),
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.height(24.dp))
    }
}

/**
 * Where the source is.
 *
 * An app that reads passports and says it keeps them to itself is asking to be taken at
 * its word. It should not have to be: the way to check any of it is to read it, so the
 * address is in the app rather than only in a listing somewhere.
 *
 * Handing a URL to ACTION_VIEW asks the browser to fetch it, and needs no INTERNET
 * permission here — this app still cannot reach the network, which is the point.
 */
@Composable
private fun SourceLink() {
    val context = LocalContext.current
    TextButton(
        onClick = {
            try {
                context.startActivity(Intent(Intent.ACTION_VIEW, SOURCE.toUri()))
            } catch (error: ActivityNotFoundException) {
                // No browser to hand it to, which is unusual but not worth a crash.
                Log.w("passauf", "Nothing here opens a link.", error)
            }
        },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(Icons.Filled.Code, contentDescription = null)
        Spacer(Modifier.padding(horizontal = 4.dp))
        Text("Get the source code")
    }
    Text(
        SOURCE.removePrefix("https://"),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.fillMaxWidth(),
        textAlign = TextAlign.Center,
    )
}

/**
 * What happens to the app switcher's preview, which differs by Android version.
 *
 * Worth saying rather than leaving people to assume the better case: before Android 13
 * that thumbnail cannot be suppressed on its own, and the only thing that removes it
 * also removes every deliberate screenshot.
 */
private fun recentsNote(): String =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        "The app switcher preview is hidden either way."
    } else {
        "On this version of Android the app switcher preview can only be hidden by " +
            "blocking screenshots as well; there is no way to remove just the one. " +
            "Newer versions hide it on their own."
    }

@Composable
private fun SettingCard(
    title: String,
    explanation: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Card {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    explanation,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.padding(horizontal = 8.dp))
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}
