package zone.ave.passauf.ui

import android.os.Build

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

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
                "Off by default. Nothing stops anyone photographing the printed page, " +
                "and being able to keep a readable copy of what is in your own document " +
                "is most of the point of this app. Worth turning on if you are sharing " +
                "your screen, if your phone sends screenshots somewhere, or if the " +
                "document is not yours.",
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

        Spacer(Modifier.height(24.dp))
    }
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
        "The app switcher preview is hidden either way. That is a picture nobody asked " +
            "to be taken."
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
