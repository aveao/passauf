package zone.ave.passauf

import android.content.Context

/**
 * The handful of choices that outlive a read.
 *
 * Not everything adjustable belongs here. Whether to read the images is a decision about
 * one document and lives on the form; whether the log records what was on the document
 * is deliberately forgotten when the app closes, so it lives on the form too. What is
 * left is one setting that is a genuine preference, and it is kept where preferences go.
 */
class Preferences(context: Context) {

    private val store = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    /**
     * Whether to stop the screen being captured while a document is on it.
     *
     * **Off by default, deliberately.** Nothing stops anyone photographing the printed
     * page, and being able to keep a legible copy of what is in your own document is
     * most of the point of this app. Blocking capture is a posture identity-verification
     * vendors adopt for their own reasons, and copying it would be taking something away
     * from the holder to no one's benefit.
     *
     * It is offered because the reasons to want it are real — a shared screen, a phone
     * that syncs its screenshots somewhere, someone else's document — and none of them
     * are ours to weigh.
     */
    var blockScreenshots: Boolean
        get() = store.getBoolean(BLOCK_SCREENSHOTS, false)
        set(value) = store.edit().putBoolean(BLOCK_SCREENSHOTS, value).apply()

    private companion object {
        const val NAME = "passauf"
        const val BLOCK_SCREENSHOTS = "blockScreenshots"
    }
}
