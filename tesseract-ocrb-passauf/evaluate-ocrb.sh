#!/usr/bin/env bash
#
# Measures the OCR-B model against the stock English one.
#
# Two numbers matter, and the second one more:
#
#   BCER  characters got wrong, out of all characters.
#   BWER  "words" got wrong. An MRZ row holds no spaces, so a row is one word, and this
#         is really the share of rows with *any* error in them.
#
# BWER is the number that decides whether the app works, because a row with one wrong
# character fails its check digits and is thrown away exactly like a row with twenty.
# The camera then tries the next frame, so a BWER of 20% is not a 20% failure rate; it
# is roughly a fifth of frames wasted.
#
# On synthetic renders this flatters itself, and that is worth being blunt about: the
# model is being asked about pictures drawn the same way the ones it learned from were
# drawn. Put real photographs in photos/ to get an honest answer.
#
# Usage:  ./evaluate-ocrb.sh [rows]

set -euo pipefail

cd "$(dirname "$0")"

ROWS="${1:-3000}"
FONT="ocrb10"
BUILD="build"
EVAL="$BUILD/eval"

if [ ! -f "$BUILD/ocrb.traineddata" ]; then
    echo "No model yet. Run ./train-ocrb.sh first." >&2
    exit 1
fi

rm -rf "$EVAL"
mkdir -p "$EVAL"

echo "==> Generating $ROWS held-out rows"
# Fresh rows, not the ones it trained on. Same generator, different draw.
cargo run --quiet --release --bin generate-mrz-corpus -- "$ROWS" > "$EVAL/corpus.txt"

# One clean and one knocked about, so the difference between them is visible. A model
# that only does well on the clean render has learned the renderer, not the typeface.
echo "==> Rendering"
text2image --text="$EVAL/corpus.txt" --outputbase="$EVAL/clean" \
    --font="$FONT" --ptsize=12 --resolution=300 --leading=32 \
    --degrade_image=false >/dev/null 2>&1
text2image --text="$EVAL/corpus.txt" --outputbase="$EVAL/rough" \
    --font="$FONT" --ptsize=12 --resolution=300 --leading=32 \
    --exposure=2 --degrade_image=true >/dev/null 2>&1

for tif in "$EVAL"/*.tif; do
    tesseract "$tif" "${tif%.tif}" --psm 6 lstm.train >/dev/null 2>&1
done

score() {
    local model="$1" listfile="$2"
    # lstmeval prints its summary on the last lines; pull the two rates out.
    lstmeval --model "$model" --eval_listfile "$listfile" 2>&1 \
        | grep -oE "BCER=[0-9.]+|BWER=[0-9.]+" \
        | tr '\n' ' '
}

for kind in clean rough; do
    echo "$EVAL/$kind.lstmf" > "$EVAL/$kind.list"
    echo
    echo "=== $kind render ==="
    printf "  stock eng   %s\n" "$(score "$BUILD/eng_best.traineddata" "$EVAL/$kind.list")"
    printf "  ocrb        %s\n" "$(score "$BUILD/ocrb.traineddata" "$EVAL/$kind.list")"
done

# Real photographs, if there are any. One image per row, with the row it holds in a
# file of the same name ending .gt.txt:
#
#   photos/passport-01.png
#   photos/passport-01.gt.txt
#
# This is the only measurement that means anything, because it is the only one where
# the pictures were not drawn by the same code that drew the training set.
if compgen -G "photos/*.gt.txt" >/dev/null; then
    echo
    echo "=== photographs ==="
    total=0
    exact=0
    for truth in photos/*.gt.txt; do
        base="${truth%.gt.txt}"
        image=$(ls "$base".{png,jpg,jpeg,tif} 2>/dev/null | head -1) || true
        [ -z "${image:-}" ] && continue
        expected=$(tr -d '\n' < "$truth")
        got=$(tesseract "$image" - --psm 7 \
                --tessdata-dir "$BUILD" -l ocrb \
                -c tessedit_char_whitelist="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<" \
                2>/dev/null | tr -d '\n\r ')
        total=$((total + 1))
        if [ "$got" = "$expected" ]; then
            exact=$((exact + 1))
        else
            echo "  $(basename "$base")"
            echo "    want $expected"
            echo "    got  $got"
        fi
    done
    echo "  $exact of $total rows read exactly."
else
    echo
    echo "No photographs in photos/, so every number above is synthetic and flattering."
    echo "Put real ones there as <name>.png plus <name>.gt.txt to find out the truth."
fi
