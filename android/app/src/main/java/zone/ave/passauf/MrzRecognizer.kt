package zone.ave.passauf

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import com.googlecode.tesseract.android.TessBaseAPI
import java.io.File

/**
 * Reads OCR-B off a picture.
 *
 * The model behind this is trained by the scripts in tesseract-ocrb-passauf/, on the
 * typeface every machine readable zone is printed in. That matters more than it sounds:
 * OCR-B exists so that 0 and O, 1 and I, 5 and S, 8 and B cannot be confused, and a
 * recogniser trained mostly on ordinary type has already learned to treat those as the
 * same shape. Stock English gets 99.6% of MRZ rows wrong. This model gets about one in
 * four hundred wrong, on renders at least.
 *
 * Not thread safe, because Tesseract is not. Build one on the thread that will use it,
 * keep it there, and [close] it when the camera goes away.
 */
class MrzRecognizer private constructor(private val tesseract: TessBaseAPI) {

    companion object {
        private const val TAG = "passauf"

        /** The name the model is filed under, so `ocrb.traineddata`. */
        private const val LANGUAGE = "ocrb"

        /**
         * Everything an MRZ can hold. Constraining the output is worth doing even though
         * the model was only ever shown these characters: it stops a smudge being read as
         * a comma, which would fail the length check and throw away a row that was
         * otherwise fine.
         */
        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<"

        /**
         * Opens the recogniser, unpacking the model on first use.
         *
         * Tesseract wants a real path rather than an asset, so the model is copied out
         * once and reused after that.
         *
         * @return null if the model cannot be unpacked or Tesseract will not start, in
         *   which case the caller should fall back to typing the fields in.
         */
        fun open(context: Context): MrzRecognizer? {
            val dataPath = context.filesDir
            val target = File(dataPath, "tessdata/$LANGUAGE.traineddata")

            if (!target.exists() || target.length() == 0L) {
                try {
                    target.parentFile?.mkdirs()
                    context.assets.open("tessdata/$LANGUAGE.traineddata").use { source ->
                        target.outputStream().use { destination -> source.copyTo(destination) }
                    }
                } catch (error: Exception) {
                    Log.e(TAG, "Could not unpack the OCR-B model.", error)
                    return null
                }
            }

            val tesseract = TessBaseAPI()
            if (!tesseract.init(dataPath.absolutePath, LANGUAGE)) {
                Log.e(TAG, "Tesseract would not start with the OCR-B model.")
                tesseract.recycle()
                return null
            }

            // The crop handed over holds the two or three rows of a zone and nothing
            // else, which is exactly one uniform block of text.
            tesseract.pageSegMode = TessBaseAPI.PageSegMode.PSM_SINGLE_BLOCK
            tesseract.setVariable(TessBaseAPI.VAR_CHAR_WHITELIST, ALPHABET)
            // The model carries no dictionaries and an MRZ holds no words, so nothing
            // should be nudging characters towards spellings of anything.
            tesseract.setVariable("load_system_dawg", "0")
            tesseract.setVariable("load_freq_dawg", "0")

            return MrzRecognizer(tesseract)
        }
    }

    /**
     * Every line of text found in the picture, in reading order.
     *
     * Whitespace is stripped rather than trusted: an MRZ has none, and Tesseract will
     * occasionally find some in a gap between characters.
     */
    fun recognize(image: Bitmap): List<String> {
        return try {
            tesseract.setImage(image)
            (tesseract.utF8Text ?: "")
                .lineSequence()
                .map { line -> line.filterNot { it.isWhitespace() } }
                .filter { it.isNotEmpty() }
                .toList()
        } catch (error: Exception) {
            Log.e(TAG, "Recognition failed on a frame.", error)
            emptyList()
        }
    }

    fun close() {
        try {
            tesseract.recycle()
        } catch (error: Exception) {
            Log.e(TAG, "Could not release Tesseract.", error)
        }
    }
}
