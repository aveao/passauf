# tesseract-ocrb-passauf

Training a Tesseract model that reads OCR-B, so passauf can get a machine readable zone
off a document with a camera instead of asking for it to be typed.

Its own package rather than part of the passauf crate. Nothing shipped depends on it,
and it is never built as part of the app or the CLI.

## Why not an off-the-shelf model

There isn't one that can be used. The two MRZ-trained Tesseract models in circulation
both fail on licensing rather than quality:

- `Shreeshrii/tessdata_ocrb` carries **no licence at all**, so it cannot be redistributed
  inside an APK. Last touched in 2019. Its advertised 0% error rate is self-evaluation on
  synthetic samples rendered in its own training fonts.
- `DaanVanVugt/tesseract-mrz` is GPL-3.0, from 2017, and its model derives from an unnamed
  `ORCB.ttf` by way of a third-party web service — a provenance chain with two unknowns in
  it.

And stock English is not an option either. Given a *perfectly clean* render of the
standard's own specimen line it inserts characters that are not there:

```
truth:  L898902C36UTO7408122F1204159ZE184226B<<<<<10
eng:    LB898902C36UTO07408122F1204159ZE184226B<<<<<10
         ^                  ^
```

## The font

`fonts/ocrb10.otf`, from CTAN's `ocr-b-outline`, traced from Norbert Schwarz's METAFONT
sources. Its licence is in `fonts/OCR-B-LICENSE.txt` and is about as permissive as they
come: *"you may freely use, modify, and/or distribute any of these files, without
limitation."* All 37 MRZ characters are present.

It has to be visible to fontconfig, because `text2image` renders through Pango:

```sh
mkdir -p ~/.local/share/fonts/passauf-ocrb
cp fonts/ocrb10.otf ~/.local/share/fonts/passauf-ocrb/
fc-cache -f ~/.local/share/fonts/passauf-ocrb
```

## Running it

```sh
./train-ocrb.sh [rows] [iterations]     # writes build/ocrb.traineddata
./evaluate-ocrb.sh [rows]               # measures it against stock eng
```

Needs Tesseract with its training tools: `text2image`, `lstmtraining`,
`combine_tessdata`, `lstmeval`. Everything lands in `build/`, which is not committed and
is reproducible from these scripts.

## How the corpus is made

`generate-mrz-corpus` builds rows the way a real document does, using passauf's own
`calculate_check_digit`, and then **puts every document back through passauf's parser
before writing it out**. A row that reads back correctly can therefore be handed straight
to the parser and must come out whole.

That check is not ceremony. The composite check digit is computed over a set of disjoint
spans of the row, and getting one of those spans wrong is the easiest mistake in the whole
standard to make. A generator with a subtly wrong composite would train the recogniser on
rows no real document carries, and then measure it against the same wrong rows — which
would look like success.

Field lengths vary widely on purpose. Runs of `<` are where a recogniser trained on
ordinary prose falls apart, and a corpus of uniformly long names never produces the short
runs while one of short names never produces the runs of twenty and more.

## What the numbers mean

`BWER` is the one to watch. An MRZ row has no spaces, so it is a single "word", and BWER
is the share of rows with *any* error in them. That is the right measure here because a
row with one wrong character fails its check digits and is discarded exactly like a row
with twenty.

It is not a failure rate, though. The camera keeps handing over frames, so a BWER of 20%
means roughly a fifth of frames are wasted, not that one scan in five fails.

## The part these numbers do not cover

The model is trained on synthetic renders and deployed against photographs. That gap is
the whole game, and no amount of synthetic evaluation will speak to it — asking the model
about pictures drawn by the same code that drew its training set is grading its own
homework. It is exactly the mistake baked into the 0% figure quoted above.

Put real photographs in `photos/` as `<name>.png` alongside `<name>.gt.txt` holding the
row they show, and `evaluate-ocrb.sh` will report how many read back exactly. That is the
only number here worth trusting.

When real photographs disagree with the synthetic scores, the fix is more realistic
degradation in `train-ocrb.sh` — or more real photographs — rather than more iterations.
