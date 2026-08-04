#!/usr/bin/env bash
#
# Fine-tunes Tesseract's English model into one that reads OCR-B, the typeface every
# machine readable zone is printed in.
#
# Stock eng is not close. On a perfectly clean synthetic render of the standard's own
# specimen it inserts characters that are not there, and Shreeshrii's published
# measurement puts it at ~45% character error on MRZ text. That is the number to beat.
#
# Fine-tuning rather than training from scratch: one font and thirty seven glyphs is a
# tiny problem, and eng already knows what printed characters look like. The unicharset
# is deliberately left alone, so no charset surgery is needed; output is constrained to
# the MRZ alphabet at recognition time instead.
#
# Everything lands in build/, which is not committed.
#
# Usage:  ./train-ocrb.sh [rows] [iterations]

set -euo pipefail

cd "$(dirname "$0")"

ROWS="${1:-20000}"
ITERATIONS="${2:-3000}"
FONT="ocrb10"
BUILD="build"
GT="$BUILD/gt"

# Not grep -q: it exits on the first match, fc-list takes SIGPIPE, and pipefail then
# reports the whole pipeline as failed on the very case that was meant to succeed.
if ! fc-list | grep -i "$FONT" >/dev/null; then
    echo "The $FONT font is not visible to fontconfig." >&2
    echo "Install it with:" >&2
    echo "  mkdir -p ~/.local/share/fonts/passauf-ocrb" >&2
    echo "  cp fonts/ocrb10.otf ~/.local/share/fonts/passauf-ocrb/" >&2
    echo "  fc-cache -f ~/.local/share/fonts/passauf-ocrb" >&2
    exit 1
fi

if [ ! -f "$BUILD/eng_best.traineddata" ]; then
    echo "Fetching the float English model, which is what --continue_from needs." >&2
    echo "(The one in /usr/share/tessdata is the integer build and cannot be tuned.)" >&2
    mkdir -p "$BUILD"
    curl -sSL -o "$BUILD/eng_best.traineddata" \
        "https://github.com/tesseract-ocr/tessdata_best/raw/main/eng.traineddata"
fi

rm -rf "$GT"
mkdir -p "$GT"

echo "==> Generating $ROWS rows"
# Every document is round-tripped through passauf's own parser before it is written, so
# a row that reads back correctly is one the parser will accept.
cargo run --quiet --release --bin generate-mrz-corpus -- "$ROWS" > "$BUILD/corpus.txt"

# Rendering settings, one line each: ptsize, exposure, degrade.
#
# Exposure is text2image's photocopier dial, and it is the cheapest way to get the
# thickened and eaten-away strokes that a phone camera produces under bad light.
# Degrade adds speckle, dilation and a little rotation. Together they are a poor
# imitation of a real photograph, which is why the model still has to be measured
# against real ones; they are enough to stop it learning that every glyph is pixel
# perfect.
RENDERS=(
    "12 0 false"
    "12 0 true"
    "12 1 true"
    "12 -1 true"
    "10 0 true"
    "14 0 true"
    "12 2 true"
    "12 -2 true"
)

index=0
for setting in "${RENDERS[@]}"; do
    read -r ptsize exposure degrade <<< "$setting"
    base="$GT/render$index"
    echo "==> Rendering ${ptsize}pt exposure=$exposure degrade=$degrade"
    text2image \
        --text="$BUILD/corpus.txt" \
        --outputbase="$base" \
        --font="$FONT" \
        --ptsize="$ptsize" \
        --exposure="$exposure" \
        --degrade_image="$degrade" \
        --resolution=300 \
        --leading=32 \
        >/dev/null 2>&1
    index=$((index + 1))
done

echo "==> Building line images into training data"
for tif in "$GT"/*.tif; do
    base="${tif%.tif}"
    # psm 6 treats the page as a block of lines, which is what a rendered corpus is.
    tesseract "$tif" "$base" --psm 6 lstm.train >/dev/null 2>&1
done

find "$GT" -name "*.lstmf" | sort > "$BUILD/all.lstmf"
total=$(wc -l < "$BUILD/all.lstmf")
if [ "$total" -lt 2 ]; then
    echo "No training data was produced; check that text2image rendered anything." >&2
    exit 1
fi

# Hold back a tenth to measure against. Held back by whole render, not by line, so the
# evaluation set contains rendering conditions the training set does not.
eval_count=$(( total / 10 ))
[ "$eval_count" -lt 1 ] && eval_count=1
head -n "$eval_count" "$BUILD/all.lstmf" > "$BUILD/list.eval"
tail -n +"$((eval_count + 1))" "$BUILD/all.lstmf" > "$BUILD/list.train"
echo "==> $total pages: $(wc -l < "$BUILD/list.train") training, $eval_count evaluation"

echo "==> Extracting the model to continue from"
combine_tessdata -e "$BUILD/eng_best.traineddata" "$BUILD/eng.lstm" >/dev/null

echo "==> Training for up to $ITERATIONS iterations"
lstmtraining \
    --model_output "$BUILD/ocrb" \
    --continue_from "$BUILD/eng.lstm" \
    --traineddata "$BUILD/eng_best.traineddata" \
    --train_listfile "$BUILD/list.train" \
    --eval_listfile "$BUILD/list.eval" \
    --max_iterations "$ITERATIONS" \
    --target_error_rate 0.01 \
    2>&1 | tail -25

echo "==> Packaging"
lstmtraining \
    --stop_training \
    --continue_from "$BUILD/ocrb_checkpoint" \
    --traineddata "$BUILD/eng_best.traineddata" \
    --model_output "$BUILD/ocrb.traineddata" \
    2>&1 | tail -3

echo
echo "Wrote $BUILD/ocrb.traineddata"
echo "Measure it with ./evaluate-ocrb.sh"
