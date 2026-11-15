"""
test_vc.py - correctness and security checks for vc_core.py

Run:  python3 test_vc.py
"""

import unittest
from itertools import combinations

import numpy as np

import vc_core as vc

SCHEMES = [("2-of-n", n) for n in range(2, 7)] + [("k-of-k", k) for k in range(2, 6)]


def demo_secret(h=40, w=60, seed=7):
    """Half-black, half-white random test image."""
    return np.random.default_rng(seed).random((h, w)) < 0.5


class TestBasisMatrices(unittest.TestCase):
    def test_contrast_and_security_conditions(self):
        for kind, value in SCHEMES:
            with self.subTest(scheme=(kind, value)):
                report = vc.verify_scheme(vc.make_scheme(kind, value))
                self.assertTrue(report["contrast_ok"])
                self.assertTrue(report["security_ok"])

    def test_pixel_expansion_matches_paper(self):
        for n in range(2, 7):
            self.assertEqual(vc.make_scheme("2-of-n", n).m_paper, n)
        for k in range(2, 6):
            self.assertEqual(vc.make_scheme("k-of-k", k).m_paper, 2 ** (k - 1))


class TestEncryptDecrypt(unittest.TestCase):
    def test_any_k_shares_recover_secret_exactly(self):
        secret = demo_secret()
        for kind, value in SCHEMES:
            scheme = vc.make_scheme(kind, value)
            shares = vc.encrypt(secret, scheme)
            for q in range(scheme.k, scheme.n + 1):
                for subset in combinations(range(scheme.n), q):
                    with self.subTest(scheme=scheme.name, subset=subset):
                        stacked = vc.stack([shares[i] for i in subset])
                        recovered = vc.clean(stacked, scheme, q)
                        self.assertTrue(np.array_equal(recovered, secret))

    def test_stacked_block_counts(self):
        secret = demo_secret()
        for kind, value in SCHEMES:
            scheme = vc.make_scheme(kind, value)
            shares = vc.encrypt(secret, scheme)
            stacked = vc.stack(shares[: scheme.k])
            s = scheme.side
            counts = stacked.reshape(secret.shape[0], s, secret.shape[1], s).sum(axis=(1, 3))
            white, black = scheme.stacked_blacks(scheme.k)
            with self.subTest(scheme=scheme.name):
                self.assertTrue(np.all(counts[~secret] == white))
                self.assertTrue(np.all(counts[secret] == black))

    def test_fewer_than_k_shares_show_nothing(self):
        """Blocks for black and white secret pixels must be equally dark,
        and clean() must refuse to decode."""
        secret = demo_secret(80, 80)
        for kind, value in SCHEMES:
            scheme = vc.make_scheme(kind, value)
            shares = vc.encrypt(secret, scheme)
            for q in range(1, scheme.k):
                for subset in combinations(range(scheme.n), q):
                    stacked = vc.stack([shares[i] for i in subset])
                    with self.subTest(scheme=scheme.name, subset=subset):
                        self.assertAlmostEqual(vc.leak_gap(stacked, secret, scheme.side), 0.0, places=9)
                        self.assertIsNone(vc.clean(stacked, scheme, q))

    def test_single_share_pattern_distribution_is_independent_of_secret(self):
        """(2,2): each of the block patterns must be about equally likely in
        a share whether the secret pixel is black or white."""
        scheme = vc.make_scheme("2-of-n", 2)
        secret = demo_secret(200, 200, seed=1)
        share = vc.encrypt(secret, scheme)[0]
        blocks = share.reshape(200, 2, 200, 2).transpose(0, 2, 1, 3).reshape(200, 200, 4)
        codes = (blocks * np.array([8, 4, 2, 1])).sum(axis=2)
        for code in np.unique(codes):
            p_black = np.mean(codes[secret] == code)
            p_white = np.mean(codes[~secret] == code)
            self.assertAlmostEqual(p_black, p_white, delta=0.02)

    def test_shares_differ_between_runs(self):
        secret = demo_secret()
        scheme = vc.make_scheme("2-of-n", 2)
        a = vc.encrypt(secret, scheme)[0]
        b = vc.encrypt(secret, scheme)[0]
        self.assertFalse(np.array_equal(a, b))

    def test_save_and_reload_round_trip(self):
        import os
        import tempfile

        secret = vc.text_to_secret("IS72")
        scheme = vc.make_scheme("2-of-n", 3)
        shares = vc.encrypt(secret, scheme)
        with tempfile.TemporaryDirectory() as tmp:
            for transparent in (False, True):
                paths = []
                for i, share in enumerate(shares[:2]):
                    path = os.path.join(tmp, f"s{i}_{transparent}.png")
                    vc.to_image(share, transparent).save(path)
                    paths.append(path)
                stacked = vc.stack([vc.load_share(p) for p in paths])
                self.assertTrue(np.array_equal(vc.clean(stacked, scheme, 2), secret))


if __name__ == "__main__":
    unittest.main(verbosity=2)
