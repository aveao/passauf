package zone.ave.passauf

import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * What an exported read is called.
 *
 * Nothing here touches Android, which is the point of keeping the naming out of the
 * screen that uses it: a filename is the last thing anyone reads before attaching
 * something to a message, so it is worth being sure about.
 */
class ExportingTest {

    private val day = LocalDate.of(2026, 8, 5)

    @Test
    fun names_carry_the_date_and_the_warning() {
        val name = Exporting.exportName("L898902C", day)
        assertEquals("passauf-export-L898-2026-08-05-NEVER-SHARE.zip", name)
    }

    /**
     * Four characters is enough to tell two exports apart and to recognise which
     * document one came off. The rest of the number stays inside the file: a name shows
     * up in the file manager, in whatever syncs that folder, and in any screenshot of a
     * listing.
     */
    @Test
    fun only_the_first_four_characters_of_the_number_appear() {
        val name = Exporting.exportName("L898902C", day)
        assertContains(name, "L898")
        assertFalse(name.contains("902C"), "the whole document number is in the filename")
    }

    /** A read that never got as far as DG1 still has to be called something. */
    @Test
    fun a_missing_document_number_just_leaves_it_out() {
        assertEquals("passauf-export-2026-08-05-NEVER-SHARE.zip", Exporting.exportName(null, day))
        assertEquals("passauf-export-2026-08-05-NEVER-SHARE.zip", Exporting.exportName("", day))
    }

    /**
     * Document numbers are printed with filler and the odd separator, and none of that
     * belongs in a filename.
     */
    @Test
    fun punctuation_and_filler_are_dropped() {
        assertEquals("passauf-export-AB12-2026-08-05-NEVER-SHARE.zip",
            Exporting.exportName("AB<12<<<", day))
        assertEquals("passauf-export-2026-08-05-NEVER-SHARE.zip",
            Exporting.exportName("<<<<", day))
        assertEquals("passauf-export-L898-2026-08-05-NEVER-SHARE.zip",
            Exporting.exportName("l898902c", day))
    }

    @Test
    fun a_log_is_named_the_same_way() {
        val name = Exporting.logName(day)
        assertEquals("passauf-log-2026-08-05-NEVER-SHARE.txt", name)
        // No document number at all: a log can come from a read that failed before it
        // learned one, and it is not worth the special case.
        assertFalse(name.contains("export"))
    }

    /** ISO order, so a folder of these sorts into the order they were made. */
    @Test
    fun dates_sort() {
        val earlier = Exporting.exportName("AAAA", LocalDate.of(2026, 8, 5))
        val later = Exporting.exportName("AAAA", LocalDate.of(2026, 12, 1))
        assert(earlier < later)
    }
}
