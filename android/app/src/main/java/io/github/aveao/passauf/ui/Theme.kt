package io.github.aveao.passauf.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// A passport-ish teal, for devices without dynamic colour.
private val Teal = Color(0xFF1B5E7E)
private val TealLight = Color(0xFF7FC4E4)

private val LightColors = lightColorScheme(primary = Teal, secondary = Color(0xFF4A6572))
private val DarkColors = darkColorScheme(primary = TealLight, secondary = Color(0xFFB0BEC5))

/** Colours that say "this passed" and "this did not", in both schemes. */
object StatusColors {
    val good: Color
        @Composable get() = if (isSystemInDarkTheme()) Color(0xFF7FD69A) else Color(0xFF1B6B3A)
    val bad: Color
        @Composable get() = MaterialTheme.colorScheme.error
    val unknown: Color
        @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
fun PassaufTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        // Material You, where the device has it.
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> DarkColors
        else -> LightColors
    }

    MaterialTheme(colorScheme = colors, content = content)
}
