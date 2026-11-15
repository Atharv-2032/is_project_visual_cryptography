"""
vc_core.py - Naor-Shamir Visual Cryptography (EUROCRYPT '94)
=============================================================

Pure algorithm code, no GUI.  Everything works on boolean numpy arrays in
which True = BLACK pixel and False = WHITE (transparent) pixel.

Idea in one paragraph
---------------------
A black-and-white secret image is split into n "shares".  Every secret pixel
is replaced, in every share, by a small block of m sub-pixels.  Which
sub-pixels are black is decided by two n x m boolean "basis matrices":

    S0  - used when the secret pixel is WHITE
    S1  - used when the secret pixel is BLACK

For each pixel we pick the right matrix, shuffle its COLUMNS with a fresh
random permutation, and give row i to share i.  Printing the shares on
transparencies and stacking them is a physical OR of the rows:

    * any k shares stacked  -> black pixels come out visibly darker than
                               white pixels, so the eye reads the secret;
    * fewer than k shares   -> the sub-pixel patterns have exactly the same
                               probability distribution for a white and a
                               black pixel, so they carry zero information
                               (perfect / one-time-pad style secrecy).

Decryption needs no key and no computation - only the human eye.

Schemes implemented (both constructions are from the original paper)
--------------------------------------------------------------------
    (2, n)  any 2 of n shares reveal the secret        m = n sub-pixels
    (k, k)  all k shares are required                  m = 2^(k-1) sub-pixels
The classic (2, 2) scheme is the n = 2 case of the first one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from itertools import combinations
from math import ceil, sqrt

import numpy as np
from PIL import Image, ImageDraw, ImageFont

# --------------------------------------------------------------------------
# 1. Basis matrices
# --------------------------------------------------------------------------


def basis_2_of_n(n: int) -> tuple[np.ndarray, np.ndarray]:
    """Naor-Shamir (2, n) construction, m = n.

    S0: every share gets the SAME single black sub-pixel  -> stacking any
        number of shares still shows 1 black sub-pixel out of n.
    S1: share i gets its OWN black sub-pixel (identity)   -> stacking q
        shares shows q black sub-pixels out of n.
    """
    if n < 2:
        raise ValueError("n must be at least 2")
    s0 = np.zeros((n, n), dtype=bool)
    s0[:, 0] = True
    s1 = np.eye(n, dtype=bool)
    return s0, s1


def basis_k_of_k(k: int) -> tuple[np.ndarray, np.ndarray]:
    """Naor-Shamir (k, k) construction, m = 2^(k-1).

    Take the ground set {1..k}.  The columns of S0 are all subsets of EVEN
    size, the columns of S1 are all subsets of ODD size; entry [i, j] is 1
    if element i belongs to subset j.

    Stacking all k rows: S0 has the empty set as a column, so one sub-pixel
    stays white; S1 has no empty column, so the block is completely black.
    Any k-1 rows of S0 and S1 are the same set of columns -> no information.
    """
    if k < 2:
        raise ValueError("k must be at least 2")
    even_cols, odd_cols = [], []
    for size in range(k + 1):
        for subset in combinations(range(k), size):
            col = np.zeros(k, dtype=bool)
            col[list(subset)] = True
            (even_cols if size % 2 == 0 else odd_cols).append(col)
    return np.array(even_cols).T, np.array(odd_cols).T


def _make_square(s0: np.ndarray, s1: np.ndarray):
    """Lay the m sub-pixels out as a side x side block so the image keeps
    its aspect ratio.

    If m divides side^2 the columns are simply repeated (e.g. the (2,2)
    scheme goes from 2 sub-pixels to the familiar 2x2 block).  Otherwise
    constant white columns are added.  Both operations are identical for S0
    and S1 and identical in every share, so they cannot leak anything.
    """
    m = s0.shape[1]
    side = ceil(sqrt(m))
    total = side * side
    if total == m:
        return s0, s1, side
    if total % m == 0:
        reps = total // m
        return np.tile(s0, (1, reps)), np.tile(s1, (1, reps)), side
    pad = np.zeros((s0.shape[0], total - m), dtype=bool)
    return np.hstack([s0, pad]), np.hstack([s1, pad]), side


@dataclass
class Scheme:
    """A (k, n) visual secret sharing scheme."""

    k: int               # shares needed to see the secret
    n: int               # shares produced
    s0: np.ndarray       # n x m basis matrix for a WHITE secret pixel
    s1: np.ndarray       # n x m basis matrix for a BLACK secret pixel
    side: int            # each secret pixel becomes a side x side block
    m_paper: int         # pixel expansion of the construction in the paper

    @property
    def m(self) -> int:
        return self.s0.shape[1]

    @property
    def name(self) -> str:
        return f"({self.k}, {self.n})"

    def stacked_blacks(self, q: int) -> tuple[int, int]:
        """Black sub-pixels per block when q shares are stacked:
        (for a white secret pixel, for a black secret pixel)."""
        white = int(np.any(self.s0[:q], axis=0).sum())
        black = int(np.any(self.s1[:q], axis=0).sum())
        return white, black

    def contrast(self, q: int | None = None) -> float:
        """Relative contrast alpha = (H(S1) - H(S0)) / m for q stacked shares."""
        white, black = self.stacked_blacks(self.k if q is None else q)
        return (black - white) / self.m


def make_scheme(kind: str, value: int) -> Scheme:
    """kind = '2-of-n' (value = n)  or  'k-of-k' (value = k)."""
    if kind == "2-of-n":
        s0, s1 = basis_2_of_n(value)
        k, n = 2, value
    elif kind == "k-of-k":
        s0, s1 = basis_k_of_k(value)
        k = n = value
    else:
        raise ValueError(f"unknown scheme kind: {kind}")
    m_paper = s0.shape[1]
    s0, s1, side = _make_square(s0, s1)
    return Scheme(k=k, n=n, s0=s0, s1=s1, side=side, m_paper=m_paper)


# --------------------------------------------------------------------------
# 2. Encryption (share generation) and decryption (stacking)
# --------------------------------------------------------------------------


def _random_permutations(h: int, w: int, m: int, seed=None) -> np.ndarray:
    """One independent random permutation of range(m) per secret pixel.

    The randomness is the whole security of the scheme (it plays the role of
    the one-time pad), so by default it comes from the operating system's
    cryptographic generator (os.urandom).  A seed is accepted only so that
    tests are repeatable.
    """
    if seed is None:
        raw = os.urandom(h * w * m * 8)
        keys = np.frombuffer(raw, dtype=np.uint64).reshape(h, w, m)
    else:
        keys = np.random.default_rng(seed).random((h, w, m))
    return np.argsort(keys, axis=2)  # sorting random keys = random shuffle


def encrypt(secret: np.ndarray, scheme: Scheme, seed=None) -> list[np.ndarray]:
    """Split a boolean secret image (True = black) into scheme.n shares.

    Each returned share is a boolean image `side` times larger in each
    direction than the secret.
    """
    secret = np.asarray(secret, dtype=bool)
    h, w = secret.shape
    side = scheme.side
    perms = _random_permutations(h, w, scheme.m, seed)

    shares = []
    for i in range(scheme.n):
        # Row i of S1 where the secret is black, row i of S0 where it is white
        rows = np.where(secret[:, :, None], scheme.s1[i], scheme.s0[i])
        # Same column permutation for every share at a given pixel
        rows = np.take_along_axis(rows, perms, axis=2)
        # (h, w, side, side) -> (h*side, w*side)
        block = rows.reshape(h, w, side, side).transpose(0, 2, 1, 3)
        shares.append(block.reshape(h * side, w * side))
    return shares


def stack(shares: list[np.ndarray]) -> np.ndarray:
    """Superimpose transparencies: a sub-pixel is black if it is black on
    ANY of the stacked shares (boolean OR)."""
    if not shares:
        raise ValueError("nothing to stack")
    shape = shares[0].shape
    if any(s.shape != shape for s in shares):
        raise ValueError("all shares must have the same size")
    return np.logical_or.reduce(shares)


def clean(stacked: np.ndarray, scheme: Scheme, q: int) -> np.ndarray | None:
    """Optional digital post-processing: recover the exact original image.

    The eye sees a noisy, low-contrast picture.  A computer can count the
    black sub-pixels in each block: a block with more black sub-pixels than
    a 'white' block can ever have must come from a black secret pixel.
    Returns None when q < k (nothing can be recovered).
    """
    if q < scheme.k:
        return None
    side = scheme.side
    h, w = stacked.shape[0] // side, stacked.shape[1] // side
    counts = stacked.reshape(h, side, w, side).sum(axis=(1, 3))
    white_level, _ = scheme.stacked_blacks(q)
    return counts > white_level


# --------------------------------------------------------------------------
# 3. Verification and statistics (used by the GUI info panel, tests, report)
# --------------------------------------------------------------------------


def _column_multiset(mat: np.ndarray) -> list:
    return sorted(tuple(int(v) for v in col) for col in mat.T)


def verify_scheme(scheme: Scheme) -> dict:
    """Check the two Naor-Shamir conditions exhaustively on the matrices.

    contrast : every set of k rows gives strictly more black sub-pixels with
               S1 than with S0.
    security : for every set of fewer than k rows, the restricted matrices
               are equal up to a column permutation -> after the random
               shuffle, white and black pixels are indistinguishable.
    """
    n, k = scheme.n, scheme.k
    contrast_ok = all(
        np.any(scheme.s1[list(r)], axis=0).sum() > np.any(scheme.s0[list(r)], axis=0).sum()
        for r in combinations(range(n), k)
    )
    security_ok = all(
        _column_multiset(scheme.s0[list(r)]) == _column_multiset(scheme.s1[list(r)])
        for q in range(1, k)
        for r in combinations(range(n), q)
    )
    white, black = scheme.stacked_blacks(k)
    return {
        "contrast_ok": contrast_ok,
        "security_ok": security_ok,
        "m": scheme.m,
        "white_blacks": white,
        "black_blacks": black,
        "alpha": scheme.contrast(),
    }


def black_ratio(img: np.ndarray) -> float:
    return float(np.mean(img))


def leak_gap(share_or_stack: np.ndarray, secret: np.ndarray, side: int) -> float:
    """Difference in mean darkness between blocks that encode black secret
    pixels and blocks that encode white ones.  ~0 means no visible leak."""
    h, w = secret.shape
    dark = share_or_stack.reshape(h, side, w, side).mean(axis=(1, 3))
    if secret.all() or not secret.any():
        return 0.0
    return float(dark[secret].mean() - dark[~secret].mean())


# --------------------------------------------------------------------------
# 4. Image helpers
# --------------------------------------------------------------------------


def binarize(img: Image.Image, max_side: int = 120, mode: str = "threshold") -> np.ndarray:
    """Any PIL image -> boolean array (True = black), at most max_side wide/tall.

    mode 'threshold' : dark pixels become black (best for text, logos, QR)
    mode 'dither'    : Floyd-Steinberg halftoning (best for photographs)
    """
    if img.mode in ("RGBA", "LA", "P"):
        rgba = img.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        img = Image.alpha_composite(background, rgba)
    gray = img.convert("L")
    scale = max_side / max(gray.size)
    if scale < 1:
        new_size = (max(1, round(gray.width * scale)), max(1, round(gray.height * scale)))
        gray = gray.resize(new_size, Image.LANCZOS)
    if mode == "dither":
        return ~np.array(gray.convert("1"), dtype=bool)
    return np.array(gray) < 128


_FONT_CANDIDATES = [
    "DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
    "arialbd.ttf",
    "Arial Bold.ttf",
]


def _load_font(size: int):
    for name in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size)
    except TypeError:  # very old Pillow
        return ImageFont.load_default()


def text_to_secret(text: str, max_side: int = 120) -> np.ndarray:
    """Render a (possibly multi-line) message as a black-on-white secret image."""
    text = text.strip() or "SECRET"
    font = _load_font(48)
    probe = ImageDraw.Draw(Image.new("L", (1, 1)))
    left, top, right, bottom = probe.multiline_textbbox((0, 0), text, font=font, spacing=8)
    pad = 14
    img = Image.new("L", (right - left + 2 * pad, bottom - top + 2 * pad), 255)
    ImageDraw.Draw(img).multiline_text(
        (pad - left, pad - top), text, font=font, fill=0, spacing=8, align="center"
    )
    return binarize(img, max_side=max_side, mode="threshold")


def to_image(arr: np.ndarray, transparent: bool = False) -> Image.Image:
    """Boolean array -> PIL image.  With transparent=True the white pixels
    are fully transparent, like a printed transparency sheet."""
    arr = np.asarray(arr, dtype=bool)
    if not transparent:
        return Image.fromarray(np.where(arr, 0, 255).astype(np.uint8)).convert("1")
    rgba = np.zeros(arr.shape + (4,), dtype=np.uint8)
    rgba[..., 3] = np.where(arr, 255, 0)
    return Image.fromarray(rgba)


def load_share(path: str) -> np.ndarray:
    """Read a share saved by this program (or scanned) back into a boolean array."""
    img = Image.open(path)
    if img.mode in ("RGBA", "LA", "P"):
        rgba = img.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        img = Image.alpha_composite(background, rgba)
    return np.array(img.convert("L")) < 128
