# Test fixtures

`gradient.jp2` and `gradient.j2k` are a 16x16 lossless JPEG 2000 image, the
same picture in the two forms a document can carry: the JP2 container and the
bare codestream. Red rises with x, green rises with y, blue is always zero, so
a decode that transposes the axes or swaps the channels fails rather than
looking plausible.

Regenerate with:

```python
from PIL import Image
img = Image.new("RGB", (16, 16))
px = img.load()
for y in range(16):
    for x in range(16):
        px[x, y] = (x * 17, y * 17, 0)
img.save("gradient.jp2", "JPEG2000", irreversible=False)
img.save("gradient.j2k", "JPEG2000", codeformat="j2k", irreversible=False)
```
