"""
app.py - Visual Cryptography Studio (Naor-Shamir) - Tkinter GUI

Run:  python3 app.py

Tabs
----
1. Encrypt & Stack   pick a secret, generate shares, tick shares to stack
2. Slide Demo        slide one transparency over another and watch the
                     secret appear only when they line up
3. Decrypt Files     load share PNGs from disk and overlay them
4. How It Works      basis matrices and the sub-pixel patterns, live
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import numpy as np
from PIL import Image, ImageTk

import vc_core as vc

APP_TITLE = "Visual Cryptography Studio - Naor-Shamir (k, n) Secret Sharing"
GREEN, RED, BLUE = "#1a7f37", "#b42318", "#1f4e9c"


def photo(arr: np.ndarray, box_w: int, box_h: int) -> ImageTk.PhotoImage:
    """Boolean image -> Tk image scaled to fit a box.

    Enlarging uses whole-number nearest-neighbour scaling so sub-pixels stay
    crisp.  Shrinking averages neighbouring sub-pixels, which is what the eye
    does when looking at a stacked transparency from a distance.
    """
    h, w = arr.shape
    img = Image.fromarray(np.where(arr, 0, 255).astype(np.uint8))
    scale = min(box_w / w, box_h / h)
    if scale >= 1:
        f = int(scale)
        img = img.resize((w * f, h * f), Image.NEAREST)
    else:
        img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.BOX)
    return ImageTk.PhotoImage(img)


class App(ttk.Frame):
    SECRET_BOX = (300, 300)     # max width, height of the secret preview
    RESULT_BOX = (480, 300)     # ... of the stacked result
    SHARE_ROW = (770, 170)      # room shared by all share thumbnails

    def __init__(self, master: tk.Tk):
        super().__init__(master, padding=8)
        self.master = master
        self.pack(fill="both", expand=True)

        self.secret: np.ndarray | None = None
        self.scheme: vc.Scheme | None = None
        self.shares: list[np.ndarray] = []
        self.loaded: list[tuple[str, np.ndarray]] = []   # Decrypt Files tab
        self._img_refs: dict[str, ImageTk.PhotoImage] = {}  # keep Tk images alive
        self._anim_job = None

        self._build_controls()
        self._build_tabs()

        # Start with a ready-made example so the window is never empty
        self.secret = vc.text_to_secret(self.text_var.get(), self.res_var.get())
        self.generate()

    # ------------------------------------------------------------------ UI
    def _build_controls(self):
        side = ttk.Frame(self, width=270)
        side.pack(side="left", fill="y", padx=(0, 8))
        side.pack_propagate(False)

        # --- 1. secret
        box = ttk.LabelFrame(side, text="1. Secret image", padding=8)
        box.pack(fill="x")
        ttk.Button(box, text="Open image file...", command=self.open_image).pack(fill="x")
        ttk.Label(box, text="or type a message (\\n = new line):").pack(anchor="w", pady=(8, 0))
        self.text_var = tk.StringVar(value="IS72")
        entry = ttk.Entry(box, textvariable=self.text_var)
        entry.pack(fill="x")
        entry.bind("<Return>", lambda _e: self.use_text())
        ttk.Button(box, text="Use this text", command=self.use_text).pack(fill="x", pady=(4, 0))

        row = ttk.Frame(box)
        row.pack(fill="x", pady=(8, 0))
        ttk.Label(row, text="Black/white by:").pack(side="left")
        self.mode_var = tk.StringVar(value="threshold")
        mode = ttk.Combobox(row, textvariable=self.mode_var, width=10, state="readonly",
                            values=("threshold", "dither"))
        mode.pack(side="right")
        mode.bind("<<ComboboxSelected>>", lambda _e: self.reload_source())

        row = ttk.Frame(box)
        row.pack(fill="x", pady=(4, 0))
        ttk.Label(row, text="Secret size (px):").pack(side="left")
        self.res_var = tk.IntVar(value=120)
        ttk.Spinbox(row, from_=40, to=240, increment=20, width=6, textvariable=self.res_var,
                    command=self.reload_source).pack(side="right")

        # --- 2. scheme
        box = ttk.LabelFrame(side, text="2. Scheme", padding=8)
        box.pack(fill="x", pady=(8, 0))
        self.kind_var = tk.StringVar(value="2-of-n")
        ttk.Radiobutton(box, text="(2, n)  any 2 shares reveal", value="2-of-n",
                        variable=self.kind_var, command=self._kind_changed).pack(anchor="w")
        ttk.Radiobutton(box, text="(k, k)  all k shares needed", value="k-of-k",
                        variable=self.kind_var, command=self._kind_changed).pack(anchor="w")
        row = ttk.Frame(box)
        row.pack(fill="x", pady=(6, 0))
        self.value_label = ttk.Label(row, text="Number of shares n:")
        self.value_label.pack(side="left")
        self.value_var = tk.IntVar(value=2)
        self.value_spin = ttk.Spinbox(row, from_=2, to=6, width=6, textvariable=self.value_var)
        self.value_spin.pack(side="right")

        # --- 3. actions
        ttk.Button(side, text="3. Generate shares", command=self.generate).pack(
            fill="x", pady=(10, 0), ipady=6)
        ttk.Button(side, text="Save shares + result...", command=self.save_all).pack(
            fill="x", pady=(6, 0))
        self.transparent_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(side, text="Save with transparent background",
                        variable=self.transparent_var).pack(anchor="w", pady=(2, 0))

        # --- info
        box = ttk.LabelFrame(side, text="Scheme facts", padding=8)
        box.pack(fill="both", expand=True, pady=(10, 0))
        self.info = tk.Text(box, width=30, height=12, wrap="word", relief="flat",
                            background=ttk.Style().lookup("TFrame", "background") or "#f0f0f0",
                            font=("TkDefaultFont", 9))
        self.info.pack(fill="both", expand=True)
        self.info.configure(state="disabled")

    def _build_tabs(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(side="left", fill="both", expand=True)
        self._build_tab_encrypt()
        self._build_tab_slide()
        self._build_tab_files()
        self._build_tab_theory()

    def _build_tab_encrypt(self):
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="  Encrypt & Stack  ")

        top = ttk.Frame(tab)
        top.pack(fill="x")
        left = ttk.LabelFrame(top, text="Secret (black & white)", padding=6)
        left.pack(side="left", fill="both", padx=(0, 6))
        ttk.Frame(left, width=self.SECRET_BOX[0], height=1).pack()   # keeps the width steady
        self.secret_label = ttk.Label(left, anchor="center")
        self.secret_label.pack(expand=True)

        right = ttk.LabelFrame(top, text="Stacked result (ticked shares overlaid)", padding=6)
        right.pack(side="left", fill="both", expand=True)
        ttk.Frame(right, width=self.RESULT_BOX[0], height=1).pack()
        holder = ttk.Frame(right, height=self.RESULT_BOX[1] + 4)        # keeps the height steady
        holder.pack(fill="x")
        holder.pack_propagate(False)
        self.result_label = ttk.Label(holder, anchor="center")
        self.result_label.pack(expand=True)
        self.status_label = ttk.Label(right, anchor="center", font=("TkDefaultFont", 10, "bold"))
        self.status_label.pack(fill="x", pady=(4, 0))
        self.clean_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Digital clean-up (count black sub-pixels per block)",
                        variable=self.clean_var, command=self.refresh_stack).pack()

        self.share_frame = ttk.LabelFrame(
            tab, text="Shares - each one alone is random noise. Tick shares to stack them.",
            padding=6)
        self.share_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.share_vars: list[tk.BooleanVar] = []

    def _build_tab_slide(self):
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="  Slide Demo  ")
        self.slide_caption = ttk.Label(tab, wraplength=760, justify="left")
        self.slide_caption.pack(anchor="w")
        self.slide_label = ttk.Label(tab, anchor="center")
        self.slide_label.pack(expand=True, fill="both")
        row = ttk.Frame(tab)
        row.pack(fill="x")
        ttk.Label(row, text="Apart").pack(side="left")
        self.slide_var = tk.DoubleVar(value=0.0)
        ttk.Scale(row, from_=0, to=1, variable=self.slide_var,
                  command=lambda _v: self.refresh_slide()).pack(
            side="left", fill="x", expand=True, padx=8)
        ttk.Label(row, text="Aligned").pack(side="left")
        ttk.Button(row, text="Animate", command=self.animate).pack(side="left", padx=(12, 0))

    def _build_tab_files(self):
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="  Decrypt Files  ")
        ttk.Label(tab, wraplength=760, justify="left", text=(
            "Receiver side: load share images that were saved earlier (or handed out to "
            "different people) and overlay them. No key and no computation is needed - "
            "stacking is just a pixel-wise OR.")).pack(anchor="w")
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=6)
        ttk.Button(row, text="Add share image(s)...", command=self.add_files).pack(side="left")
        ttk.Button(row, text="Clear", command=self.clear_files).pack(side="left", padx=6)
        self.files_status = ttk.Label(row, text="No shares loaded.")
        self.files_status.pack(side="left", padx=6)
        self.files_label = ttk.Label(tab, anchor="center")
        self.files_label.pack(expand=True, fill="both")

    def _build_tab_theory(self):
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="  How It Works  ")
        self.theory_text = tk.Text(tab, height=15, wrap="word", font=("TkFixedFont", 10))
        self.theory_text.pack(fill="x")
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(6, 2))
        ttk.Label(row, text="One secret pixel, encoded with a fresh random column shuffle:",
                  font=("TkDefaultFont", 10, "bold")).pack(side="left")
        ttk.Button(row, text="Shuffle again", command=self.draw_theory).pack(side="right")
        self.theory_canvas = tk.Canvas(tab, height=230, background="white",
                                       highlightthickness=1, highlightbackground="#bbbbbb")
        self.theory_canvas.pack(fill="both", expand=True)

    # ------------------------------------------------------------- secret
    def _set_image(self, label: ttk.Label, key: str, arr: np.ndarray, w: int, h: int):
        self._img_refs[key] = photo(arr, w, h)
        label.configure(image=self._img_refs[key])

    def open_image(self):
        path = filedialog.askopenfilename(
            title="Choose the secret image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.webp"), ("All files", "*.*")])
        if not path:
            return
        try:
            self._source = Image.open(path)
            self._source.load()
        except Exception as exc:  # unreadable or not an image
            messagebox.showerror("Cannot open image", str(exc))
            return
        self._source_kind = "image"
        self.reload_source(regenerate=True)

    def use_text(self):
        self._source_kind = "text"
        self.reload_source(regenerate=True)

    def reload_source(self, regenerate: bool = True):
        """Rebuild the boolean secret from the current source and settings."""
        try:
            size = int(self.res_var.get())
        except (tk.TclError, ValueError):
            size = 120
        size = min(max(size, 20), 300)
        if getattr(self, "_source_kind", "text") == "image":
            self.secret = vc.binarize(self._source, size, self.mode_var.get())
        else:
            self.secret = vc.text_to_secret(self.text_var.get().replace("\\n", "\n"), size)
        if regenerate:
            self.generate()

    # ------------------------------------------------------------- scheme
    def _kind_changed(self):
        if self.kind_var.get() == "2-of-n":
            self.value_label.configure(text="Number of shares n:")
            self.value_spin.configure(from_=2, to=6)
        else:
            self.value_label.configure(text="Number of shares k:")
            self.value_spin.configure(from_=2, to=5)
            if self.value_var.get() > 5:
                self.value_var.set(5)

    def generate(self):
        if self.secret is None:
            return
        kind = self.kind_var.get()
        try:
            value = int(self.value_var.get())
        except (tk.TclError, ValueError):
            value = 2
        value = min(max(value, 2), 6 if kind == "2-of-n" else 5)
        self.value_var.set(value)

        self.scheme = vc.make_scheme(kind, value)
        self.shares = vc.encrypt(self.secret, self.scheme)

        self._set_image(self.secret_label, "secret", self.secret, *self.SECRET_BOX)
        self._rebuild_share_row()
        self.refresh_stack()
        self.slide_var.set(0.0)
        self.refresh_slide()
        self.refresh_info()
        self.draw_theory()

    def _rebuild_share_row(self):
        for child in self.share_frame.winfo_children():
            child.destroy()
        self.share_vars = []
        thumb_w = min(240, self.SHARE_ROW[0] // len(self.shares) - 16)
        for i, share in enumerate(self.shares):
            cell = ttk.Frame(self.share_frame)
            cell.pack(side="left", expand=True)
            label = ttk.Label(cell)
            label.pack()
            self._set_image(label, f"share{i}", share, thumb_w, self.SHARE_ROW[1])
            var = tk.BooleanVar(value=i < self.scheme.k)   # tick exactly k to start
            self.share_vars.append(var)
            ttk.Checkbutton(cell, text=f"Share {i + 1}", variable=var,
                            command=self.refresh_stack).pack()

    # -------------------------------------------------------------- stack
    def refresh_stack(self):
        if not self.shares:
            return
        picked = [s for s, v in zip(self.shares, self.share_vars) if v.get()]
        q, k = len(picked), self.scheme.k
        if q == 0:
            blank = np.zeros_like(self.shares[0])
            self._set_image(self.result_label, "result", blank, *self.RESULT_BOX)
            self.status_label.configure(text="Tick at least one share", foreground="black")
            return
        stacked = vc.stack(picked)
        shown = stacked
        if self.clean_var.get():
            cleaned = vc.clean(stacked, self.scheme, q)
            if cleaned is not None:
                shown = cleaned
        self._set_image(self.result_label, "result", shown, *self.RESULT_BOX)

        gap = vc.leak_gap(stacked, self.secret, self.scheme.side)
        if q >= k:
            self.status_label.configure(
                foreground=GREEN,
                text=f"{q} share(s) stacked, k = {k}:  SECRET REVEALED  (contrast {gap:.0%})")
        else:
            self.status_label.configure(
                foreground=RED,
                text=f"{q} share(s) stacked, k = {k}:  NOTHING LEAKS  (contrast {gap:.0%})")

    # -------------------------------------------------------------- slide
    def _slide_layers(self):
        """Fixed layer = share 1.  Moving layer = shares 2..k already stacked."""
        k = self.scheme.k
        moving = vc.stack(self.shares[1:k])
        return self.shares[0], moving

    def refresh_slide(self):
        if not self.shares:
            return
        fixed, moving = self._slide_layers()
        h, w = fixed.shape
        offset = int(round((1.0 - float(self.slide_var.get())) * w))
        canvas = np.zeros((h, 2 * w), dtype=bool)
        canvas[:, :w] |= fixed
        canvas[:, offset:offset + w] |= moving
        self._set_image(self.slide_label, "slide", canvas, 840, 420)
        k = self.scheme.k
        who = "Share 2" if k == 2 else f"Shares 2-{k} (already stacked)"
        self.slide_caption.configure(text=(
            f"Share 1 is fixed on the left. {who} slides over it. Even one sub-pixel of "
            "misalignment hides the secret; it appears only when the sheets line up exactly."))

    def animate(self):
        if self._anim_job is not None:
            self.after_cancel(self._anim_job)
            self._anim_job = None
        steps = 60

        def step(i=0):
            self.slide_var.set(i / steps)
            self.refresh_slide()
            if i < steps:
                self._anim_job = self.after(30, step, i + 1)
            else:
                self._anim_job = None

        step()

    # -------------------------------------------------------------- files
    def add_files(self):
        paths = filedialog.askopenfilenames(
            title="Choose share images", filetypes=[("PNG images", "*.png"), ("All files", "*.*")])
        for path in paths:
            try:
                arr = vc.load_share(path)
            except Exception as exc:
                messagebox.showerror("Cannot open share", f"{path}\n{exc}")
                continue
            if self.loaded and arr.shape != self.loaded[0][1].shape:
                messagebox.showerror(
                    "Size mismatch",
                    f"{os.path.basename(path)} is {arr.shape[1]}x{arr.shape[0]} but the shares "
                    f"already loaded are {self.loaded[0][1].shape[1]}x{self.loaded[0][1].shape[0]}.")
                continue
            self.loaded.append((os.path.basename(path), arr))
        self.refresh_files()

    def clear_files(self):
        self.loaded = []
        self.files_label.configure(image="")
        self.refresh_files()

    def refresh_files(self):
        if not self.loaded:
            self.files_status.configure(text="No shares loaded.")
            return
        names = ", ".join(name for name, _ in self.loaded)
        self.files_status.configure(text=f"{len(self.loaded)} loaded: {names}")
        stacked = vc.stack([arr for _, arr in self.loaded])
        self._set_image(self.files_label, "files", stacked, 840, 480)

    def save_all(self):
        if not self.shares:
            return
        folder = filedialog.askdirectory(title="Choose a folder for the share images")
        if not folder:
            return
        transparent = self.transparent_var.get()
        try:
            vc.to_image(self.secret).save(os.path.join(folder, "secret_bw.png"))
            for i, share in enumerate(self.shares, start=1):
                vc.to_image(share, transparent).save(os.path.join(folder, f"share_{i}.png"))
            picked = [s for s, v in zip(self.shares, self.share_vars) if v.get()] or self.shares
            vc.to_image(vc.stack(picked)).save(os.path.join(folder, "stacked.png"))
        except OSError as exc:
            messagebox.showerror("Could not save", str(exc))
            return
        messagebox.showinfo("Saved", f"Saved secret_bw.png, {len(self.shares)} share file(s) "
                                     f"and stacked.png to:\n{folder}")

    # --------------------------------------------------------------- info
    def refresh_info(self):
        sc, rep = self.scheme, vc.verify_scheme(self.scheme)
        h, w = self.secret.shape
        ratios = ", ".join(f"{vc.black_ratio(s):.1%}" for s in self.shares)
        lines = [
            f"Scheme: {sc.name} threshold",
            f"Shares produced (n): {sc.n}",
            f"Shares needed (k): {sc.k}",
            "",
            f"Sub-pixels per pixel: {sc.m} ({sc.side}x{sc.side} block; {sc.m_paper} in the paper)",
            f"Secret {w}x{h} px -> shares {w * sc.side}x{h * sc.side} px",
            "",
            f"Stack of k shares: white pixel = {rep['white_blacks']}/{sc.m} black, "
            f"black pixel = {rep['black_blacks']}/{sc.m} black",
            f"Relative contrast: {rep['alpha']:.3f}",
            "",
            f"Black in each share: {ratios}",
            "",
            f"Contrast condition: {'PASS' if rep['contrast_ok'] else 'FAIL'}",
            f"Security condition: {'PASS' if rep['security_ok'] else 'FAIL'}",
        ]
        self.info.configure(state="normal")
        self.info.delete("1.0", "end")
        self.info.insert("1.0", "\n".join(lines))
        self.info.configure(state="disabled")

    # ------------------------------------------------------------- theory
    @staticmethod
    def _matrix_rows(mat: np.ndarray) -> list[str]:
        return ["[ " + " ".join("1" if v else "0" for v in row) + " ]" for row in mat]

    def draw_theory(self):
        sc = self.scheme
        if sc is None:
            return
        white, black = sc.stacked_blacks(sc.k)
        s0, s1 = self._matrix_rows(sc.s0), self._matrix_rows(sc.s1)
        width = max(len(s0[0]), 12)
        text = [
            f"Naor-Shamir {sc.name} scheme: {sc.n} shares, any {sc.k} reveal the secret.",
            "Rows = shares, columns = sub-pixels, 1 = black sub-pixel.",
            "",
            "S0 (white pixel)".ljust(width + 6) + "S1 (black pixel)",
        ]
        text += [a.ljust(width + 6) + b for a, b in zip(s0, s1)]
        text += [
            "",
            "For every secret pixel: choose S0 or S1, shuffle its columns randomly,",
            "give row i to share i. Stacking shares = OR of their rows.",
            f"OR of {sc.k} rows: {white} black for a white pixel, {black} black for a black pixel",
            f"-> the black pixel is darker by {black - white} of {sc.m} sub-pixels (the contrast).",
            f"Fewer than {sc.k} rows of S0 and S1 hold the same columns -> no information.",
        ]
        self.theory_text.configure(state="normal")
        self.theory_text.delete("1.0", "end")
        self.theory_text.insert("1.0", "\n".join(text))
        self.theory_text.configure(state="disabled", height=len(text) + 1)

        # --- picture: one white and one black pixel with a fresh shuffle
        cv = self.theory_canvas
        cv.delete("all")
        cell = {2: 24, 3: 17}.get(sc.side, 13)
        block = cell * sc.side
        gap_x, x0, y0 = 30, 120, 40
        perm = np.random.permutation(sc.m)
        for r, (title, mat) in enumerate((("White pixel", sc.s0), ("Black pixel", sc.s1))):
            y = y0 + r * (block + 46)
            cv.create_text(12, y + block / 2, text=title, anchor="w",
                           font=("TkDefaultFont", 10, "bold"))
            shuffled = mat[:, perm]
            columns = [(f"Share {i + 1}", shuffled[i]) for i in range(sc.n)]
            columns.append((f"Stack of {sc.k}", np.any(shuffled[: sc.k], axis=0)))
            for c, (name, bits) in enumerate(columns):
                x = x0 + c * (block + gap_x) + (18 if c == sc.n else 0)
                is_stack = c == sc.n
                if r == 0:
                    cv.create_text(x + block / 2, y - 14, text=name,
                                   fill=BLUE if is_stack else "black",
                                   font=("TkDefaultFont", 9, "bold" if is_stack else "normal"))
                for j, bit in enumerate(bits):
                    cx, cy = x + (j % sc.side) * cell, y + (j // sc.side) * cell
                    cv.create_rectangle(cx, cy, cx + cell, cy + cell,
                                        fill="black" if bit else "white", outline="#999999")
                if is_stack:
                    cv.create_text(x + block + 10, y + block / 2, anchor="w",
                                   text=f"{int(bits.sum())}/{sc.m} black")


def main():
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1180x790")
    root.minsize(1100, 740)
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
