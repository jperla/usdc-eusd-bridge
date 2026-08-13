#!/usr/bin/env python3
"""Executable scalar-algebra witnesses for FROST/CLSAG nonce reuse.

This deliberately models the response shape used after FROST has combined a
hiding nonce d and binding nonce e with transcript-dependent factor rho:

    s_i = d + rho_i * e - p_i * x  (mod q)

For Serai's CLSAG adapter, p_i is the key challenge and x is the weighted
secret share. Signs differ in IETF FROST, but the extraction result is the
same after changing the corresponding coefficient.

The script proves two distinct claims:

1. If the same *effective* nonce r = d + rho*e answers two different
   challenges, two responses recover x.
2. If one two-nonce preprocessing pair (d,e) is reused with changing binding
   factors, three generic responses recover both e and x. Two generic
   responses alone leave one scalar degree of freedom unless additional
   structure or a discrete-log break is available.

This is an algebraic state-machine witness, not a cryptographic implementation
or a claim that public nonce commitments reveal d/e scalars.
"""

from __future__ import annotations

import argparse
import unittest
from dataclasses import dataclass


# Scalar-field order used by Ed25519/Ristretto255.
Q = 2**252 + 27742317777372353535851937790883648493


def inv(value: int) -> int:
    """Return a nonzero scalar's inverse, rejecting degenerate witnesses."""

    reduced = value % Q
    if reduced == 0:
        raise ValueError("singular scalar")
    return pow(reduced, -1, Q)


def response(*, hiding: int, binding: int, rho: int, challenge: int, share: int) -> int:
    """Compute s = d + rho*e - p*x in the scalar field."""

    return (hiding + rho * binding - challenge * share) % Q


def extract_from_same_effective_nonce(
    *, response_1: int, response_2: int, challenge_1: int, challenge_2: int
) -> int:
    """Recover x when rho (and therefore effective nonce r) is identical."""

    # s1-s2 = (p2-p1)*x
    return ((response_1 - response_2) * inv(challenge_2 - challenge_1)) % Q


@dataclass(frozen=True)
class ThreeReuseExtraction:
    binding_nonce: int
    secret_share: int


def extract_from_three_pair_reuses(
    *,
    responses: tuple[int, int, int],
    rhos: tuple[int, int, int],
    challenges: tuple[int, int, int],
) -> ThreeReuseExtraction:
    """Recover e and x from three nondegenerate reuses of one (d,e) pair."""

    s1, s2, s3 = (value % Q for value in responses)
    rho1, rho2, rho3 = (value % Q for value in rhos)
    p1, p2, p3 = (value % Q for value in challenges)

    # Subtract response equations to eliminate d:
    #   s1-s2 = (rho1-rho2)e + (p2-p1)x
    #   s1-s3 = (rho1-rho3)e + (p3-p1)x
    a1, b1, y1 = rho1 - rho2, p2 - p1, s1 - s2
    a2, b2, y2 = rho1 - rho3, p3 - p1, s1 - s3
    determinant = (a1 * b2 - a2 * b1) % Q
    determinant_inverse = inv(determinant)

    binding_nonce = ((y1 * b2 - y2 * b1) * determinant_inverse) % Q
    secret_share = ((a1 * y2 - a2 * y1) * determinant_inverse) % Q
    return ThreeReuseExtraction(binding_nonce, secret_share)


def alternate_two_response_opening(
    *,
    responses: tuple[int, int],
    rhos: tuple[int, int],
    challenges: tuple[int, int],
    alternate_share: int,
) -> tuple[int, int]:
    """Construct (d',e') fitting two responses for any chosen x'.

    This demonstrates why two generic transcript-dependent binding factors do
    not by themselves give the elementary scalar extraction used in the
    same-effective-nonce case. Public D/E commitments bind the real opening,
    but obtaining their scalars remains a discrete-log problem.
    """

    s1, s2 = (value % Q for value in responses)
    rho1, rho2 = (value % Q for value in rhos)
    p1, p2 = (value % Q for value in challenges)
    x_alt = alternate_share % Q
    e_alt = ((s1 - s2 - (p2 - p1) * x_alt) * inv(rho1 - rho2)) % Q
    d_alt = (s1 - rho1 * e_alt + p1 * x_alt) % Q
    return d_alt, e_alt


class NonceReuseWitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hiding = 0xD15EA5E
        self.binding = 0xB1D1
        self.share = 0x5EC2E7

    def test_two_responses_extract_when_effective_nonce_is_reused(self) -> None:
        rho = 41
        p1, p2 = 101, 313
        s1 = response(
            hiding=self.hiding,
            binding=self.binding,
            rho=rho,
            challenge=p1,
            share=self.share,
        )
        s2 = response(
            hiding=self.hiding,
            binding=self.binding,
            rho=rho,
            challenge=p2,
            share=self.share,
        )
        self.assertEqual(
            extract_from_same_effective_nonce(
                response_1=s1,
                response_2=s2,
                challenge_1=p1,
                challenge_2=p2,
            ),
            self.share,
        )

    def test_three_generic_pair_reuses_extract_binding_nonce_and_share(self) -> None:
        rhos = (7, 29, 61)
        challenges = (103, 211, 401)
        responses = tuple(
            response(
                hiding=self.hiding,
                binding=self.binding,
                rho=rho,
                challenge=challenge,
                share=self.share,
            )
            for rho, challenge in zip(rhos, challenges, strict=True)
        )
        extracted = extract_from_three_pair_reuses(
            responses=responses,
            rhos=rhos,
            challenges=challenges,
        )
        self.assertEqual(extracted.binding_nonce, self.binding)
        self.assertEqual(extracted.secret_share, self.share)

    def test_two_generic_pair_reuses_have_an_alternate_scalar_opening(self) -> None:
        rhos = (17, 43)
        challenges = (109, 257)
        responses = tuple(
            response(
                hiding=self.hiding,
                binding=self.binding,
                rho=rho,
                challenge=challenge,
                share=self.share,
            )
            for rho, challenge in zip(rhos, challenges, strict=True)
        )
        alternate_share = self.share + 1
        alternate_hiding, alternate_binding = alternate_two_response_opening(
            responses=responses,
            rhos=rhos,
            challenges=challenges,
            alternate_share=alternate_share,
        )
        alternate_responses = tuple(
            response(
                hiding=alternate_hiding,
                binding=alternate_binding,
                rho=rho,
                challenge=challenge,
                share=alternate_share,
            )
            for rho, challenge in zip(rhos, challenges, strict=True)
        )
        self.assertNotEqual(alternate_share, self.share)
        self.assertEqual(alternate_responses, responses)

    def test_degenerate_extraction_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "singular scalar"):
            extract_from_three_pair_reuses(
                responses=(1, 2, 3),
                rhos=(5, 5, 5),
                challenges=(7, 11, 13),
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run the executable nonce-reuse witnesses",
    )
    args = parser.parse_args()
    if not args.selftest:
        parser.error("pass --selftest")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NonceReuseWitnessTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
