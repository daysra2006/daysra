from __future__ import annotations

import pytest

from daysra.core.ulid import CROCKFORD_BASE32, generate_ulid, is_valid_ulid


class TestUlidGeneration:
    """Validate ULID generation logic."""

    def test_length_and_crockford_alphabet(self) -> None:
        ulid = generate_ulid()
        assert len(ulid) == 26
        assert all(c in CROCKFORD_BASE32 for c in ulid)

    def test_crockford_alphabet_contents(self) -> None:
        # Crockford Base32 excludes I, L, O, and U to prevent misreads and profanity
        assert len(CROCKFORD_BASE32) == 32
        for excluded in ["I", "L", "O", "U"]:
            assert excluded not in CROCKFORD_BASE32

    def test_generation_with_explicit_timestamp(self) -> None:
        # Timestamp 0 should produce '0' as leading characters
        ulid_zero = generate_ulid(timestamp_ms=0)
        assert len(ulid_zero) == 26
        assert ulid_zero.startswith("0000000000")

        # Specific timestamp: 1700000000000 ms
        ulid_specific = generate_ulid(timestamp_ms=1700000000000)
        assert len(ulid_specific) == 26
        assert all(c in CROCKFORD_BASE32 for c in ulid_specific)

    def test_timestamp_monotonicity(self) -> None:
        # Higher timestamp should produce lexicographically greater or equal prefix
        t1 = 1_000_000
        t2 = 2_000_000
        ulid1 = generate_ulid(timestamp_ms=t1)
        ulid2 = generate_ulid(timestamp_ms=t2)

        # 48 bits of timestamp correspond to the first 10 characters in Base32
        prefix1 = ulid1[:10]
        prefix2 = ulid2[:10]
        assert prefix1 < prefix2
        assert ulid1 < ulid2

    def test_uniqueness_with_same_timestamp(self) -> None:
        # When called with the same millisecond timestamp, 80 bits of randomness
        # ensure IDs are practically distinct
        fixed_time = 1_700_000_000_000
        ids = {generate_ulid(timestamp_ms=fixed_time) for _ in range(50)}
        assert len(ids) == 50

    def test_default_timestamp_uses_current_time(self) -> None:
        ulid1 = generate_ulid()
        assert len(ulid1) == 26
        assert is_valid_ulid(ulid1)


class TestIsValidUlid:
    """Validate ULID format check function."""

    def test_valid_uppercase_ulids(self) -> None:
        assert is_valid_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV")
        assert is_valid_ulid("00000000000000000000000000")
        assert is_valid_ulid("7ZZZZZZZZZZZZZZZZZZZZZZZZZ")

    def test_valid_lowercase_converted_to_uppercase(self) -> None:
        # The implementation upper()s before checking against CROCKFORD_BASE32
        assert is_valid_ulid("01arz3ndektsv4rrffq69g5fav")

    @pytest.mark.parametrize(
        "invalid_input",
        [
            None,
            12345,
            12.34,
            [],
            {},
            True,
            b"01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ],
    )
    def test_reject_non_string_types(self, invalid_input: object) -> None:
        assert is_valid_ulid(invalid_input) is False  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "invalid_length",
        [
            "",
            "01ARZ3NDEKTSV4RRFFQ69G5FA",  # 25 chars
            "01ARZ3NDEKTSV4RRFFQ69G5FAVV",  # 27 chars
            "01ARZ",
        ],
    )
    def test_reject_invalid_length(self, invalid_length: str) -> None:
        assert is_valid_ulid(invalid_length) is False

    @pytest.mark.parametrize("excluded_char", ["I", "L", "O", "U", "i", "l", "o", "u"])
    def test_reject_crockford_excluded_characters(self, excluded_char: str) -> None:
        # Replace the first character with an excluded letter
        candidate = excluded_char + "1ARZ3NDEKTSV4RRFFQ69G5FAV"
        assert is_valid_ulid(candidate) is False

    @pytest.mark.parametrize(
        "special_char",
        ["-", "_", " ", "\t", "\n", "@", "!", "$", ".", ":"],
    )
    def test_reject_punctuation_and_whitespace(self, special_char: str) -> None:
        candidate = special_char + "1ARZ3NDEKTSV4RRFFQ69G5FAV"
        assert is_valid_ulid(candidate) is False

    def test_reject_non_ascii_characters(self) -> None:
        candidate = "✓1ARZ3NDEKTSV4RRFFQ69G5FAV"
        assert is_valid_ulid(candidate) is False
