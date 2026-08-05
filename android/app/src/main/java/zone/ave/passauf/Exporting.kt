package zone.ave.passauf

import android.content.Context
import android.net.Uri
import java.io.File
import java.time.LocalDate
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Writing a read out to a file the user picks.
 *
 * Deliberately a save rather than a share. Handing this to a share sheet frames it as
 * something to send somewhere, which is the opposite of what it is: the contents of a
 * passport belong on the holder's own disk, if anywhere. A save also asks for nothing —
 * no storage permission, no directory handed over — because the system returns a single
 * URI for the one file the user named, and it is gone again afterwards.
 *
 * That is also why it is not ACTION_OPEN_DOCUMENT_TREE. A tree grants write access to
 * an entire directory for as long as the app cares to keep it.
 */
object Exporting {

    /**
     * What a read is saved as.
     *
     * The marker in the middle is doing real work. The zip holds a face, a name, a date
     * of birth and a document number, which together are the key to the chip it came
     * off; a filename is the last thing anyone reads before attaching something to a
     * message.
     *
     * Only the first four characters of the document number, and only so two exports can
     * be told apart and matched to their document. A filename shows up in the file
     * manager, in whatever syncs the folder, and in any screenshot of a listing. The
     * whole number is inside the zip, where it is already among worse.
     */
    fun exportName(documentNumber: String?, today: LocalDate): String {
        val cleaned = documentNumber
            ?.filter { it.isLetterOrDigit() }
            ?.take(4)
            ?.uppercase()
            ?.takeIf { it.isNotEmpty() }
        val middle = if (cleaned != null) "$cleaned-" else ""
        return "passauf-export-$middle$today-NEVER-SHARE.zip"
    }

    /** What a log is saved as. Same reasoning, and a log can hold more than the files do. */
    fun logName(today: LocalDate): String = "passauf-log-$today-NEVER-SHARE.txt"

    /**
     * Stream a read's files into the URI the user named, as a zip.
     *
     * Streamed rather than assembled first: a read with images in it runs to megabytes,
     * and there is no reason for a second copy of a passport to exist in memory or in
     * the cache while this happens.
     */
    fun zipInto(context: Context, target: Uri, files: List<File>) {
        context.contentResolver.openOutputStream(target)?.use { sink ->
            ZipOutputStream(sink.buffered()).use { zip ->
                for (file in files) {
                    if (!file.exists()) {
                        continue
                    }
                    zip.putNextEntry(ZipEntry(file.name))
                    file.inputStream().use { source -> source.copyTo(zip) }
                    zip.closeEntry()
                }
            }
        }
    }

    /**
     * Unpack a zip this app wrote earlier, and say where its files went.
     *
     * Entry names are reduced to bare filenames. A zip is an untrusted archive even when
     * this app wrote the last one, and an entry called `../../databases/x` would
     * otherwise be written exactly there.
     *
     * Nothing is interpreted here. What the files amount to is the library's question,
     * and it answers it by parsing them rather than by being told.
     */
    fun importFrom(context: Context, source: Uri, into: File): List<File> {
        val written = mutableListOf<File>()
        into.mkdirs()

        context.contentResolver.openInputStream(source)?.use { stream ->
            ZipInputStream(stream.buffered()).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    val name = File(entry.name).name
                    if (entry.isDirectory || name.isEmpty()) {
                        continue
                    }
                    val target = File(into, name)
                    target.outputStream().use { sink -> zip.copyTo(sink) }
                    written.add(target)
                }
            }
        }

        return written
    }

    /** Write text out to the URI the user named. */
    fun textInto(context: Context, target: Uri, text: String) {
        context.contentResolver.openOutputStream(target)?.use { sink ->
            sink.write(text.toByteArray())
        }
    }

    /** Copy one file out to the URI the user named. */
    fun fileInto(context: Context, target: Uri, file: File) {
        context.contentResolver.openOutputStream(target)?.use { sink ->
            file.inputStream().use { source -> source.copyTo(sink) }
        }
    }
}
