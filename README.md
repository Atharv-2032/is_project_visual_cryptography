# Visual Cryptography Studio — Naor–Shamir (k, n) Visual Secret Sharing

Information Security (IS72) — Project-Based Learning (Algorithm Implementation)

A black-and-white secret image is split into **n shares** that each look like
random noise. Stacking any **k** of them (printed on transparencies, or overlaid
on screen) reveals the secret to the naked eye — **decryption needs no key and no
computation**. Fewer than k shares reveal nothing at all, even to an attacker
with unlimited computing power.

Algorithm: M. Naor and A. Shamir, "Visual Cryptography", EUROCRYPT 1994.

## Run it

```bash
# one-time setup (Ubuntu / Debian)
sudo apt install python3-tk          # Tkinter, if not already installed
pip install -r requirements.txt      # Pillow + NumPy
#   if pip refuses on Ubuntu 23.04+:  sudo apt install python3-pil python3-pil.imagetk python3-numpy

python3 app.py                       # start the GUI
python3 test_vc.py                   # run the 8 automated checks
```

Python 3.9 or newer.

## Files

| File | What it is |
| --- | --- |
| `vc_core.py` | The algorithm: basis matrices, share generation, stacking, verification. No GUI code. |
| `app.py` | Tkinter GUI with four tabs. |
| `test_vc.py` | Automated tests of correctness and of the security condition. |
| `samples/` | Demo inputs: `padlock.png`, `qr_code.png`, `shaded_sphere.png` (for dithering). |
| `screenshots/` | Screenshots of the running app, used in the report. |

## Schemes implemented

| Scheme | Meaning | Sub-pixels per pixel in the paper |
| --- | --- | --- |
| (2, n), n = 2…6 | any 2 of n shares reveal the secret | n |
| (k, k), k = 2…5 | all k shares are required | 2^(k−1) |

The classic (2, 2) scheme is the first row with n = 2.

## Suggested live demo (about 3 minutes)

1. Start the app. It opens on the (2, 2) scheme with the text `IS72` already
   split: two noise shares, and the stacked result showing the text.
2. **Untick Share 2.** The result is pure noise and the status line turns red:
   "NOTHING LEAKS (contrast 0%)". Tick it again — the secret returns.
3. Press **Generate shares** a few times: the shares change every time
   (fresh randomness), the stacked result does not.
4. Open the **Slide Demo** tab and press **Animate**: one transparency slides
   over the other and the secret snaps into view only when they align.
5. Back on the first tab, choose **(2, n)** with n = 4, Generate, and tick any
   two shares — every pair works.
6. Choose **(k, k)** with k = 3 and open `samples/padlock.png`. Two shares show
   nothing; the third reveals it. Tick **Digital clean-up** for an exact copy.
7. Open `samples/qr_code.png` with (2, 2) and clean-up on: the reconstructed
   QR code scans with a phone.
8. **How It Works** tab: the basis matrices S0 and S1 and the sub-pixel blocks
   for one white and one black pixel. Press **Shuffle again** to show the
   random column permutation.
9. Optional: **Save shares + result…**, then load the PNGs in the
   **Decrypt Files** tab to play the receiver.

For a physical demo, tick "Save with transparent background", print two
shares at the same size on transparency sheets, and overlay them by hand.
