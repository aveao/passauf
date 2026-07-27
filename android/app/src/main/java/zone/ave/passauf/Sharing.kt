package zone.ave.passauf

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File

/**
 * Handing a document's files to whatever the user wants to open them with.
 *
 * The files live in the app's own storage, so they go out through the
 * FileProvider declared in the manifest rather than as raw paths.
 */
object Sharing {

    private fun uriFor(context: Context, file: File): Uri =
        FileProvider.getUriForFile(context, "${context.packageName}.files", file)

    private fun mimeTypeFor(file: File): String = when (file.extension.lowercase()) {
        "jpeg", "jpg" -> "image/jpeg"
        "jp2" -> "image/jp2"
        "txt", "log" -> "text/plain"
        else -> "application/octet-stream"
    }

    /** Share one file. */
    fun shareFile(context: Context, file: File) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mimeTypeFor(file)
            putExtra(Intent.EXTRA_STREAM, uriFor(context, file))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share ${file.name}"))
    }

    /** Share everything a read wrote out. */
    fun shareAll(context: Context, files: List<File>) {
        if (files.isEmpty()) {
            return
        }
        if (files.size == 1) {
            shareFile(context, files.first())
            return
        }
        val uris = ArrayList(files.map { uriFor(context, it) })
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            // Mixed types, and the share sheet only takes one.
            type = "*/*"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share ${files.size} files"))
    }

    /**
     * Write the read's log out next to its files and share that.
     *
     * Useful for reporting a document passauf cannot read, which is the point
     * of keeping the log around at all.
     */
    fun shareLog(context: Context, directory: File?, log: List<String>) {
        val target = File(directory ?: context.cacheDir, "passauf-log.txt")
        target.writeText(log.joinToString("\n"))
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uriFor(context, target))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share the log"))
    }
}
