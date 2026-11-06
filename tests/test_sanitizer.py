from __future__ import annotations

from daysra.core.sanitizer import (
    CONTROL_SEQUENCE,
    sanitize_terminal_text,
    strip_control_characters,
)


class TestStripControlCharactersCsi:
    """Validate ANSI CSI (Control Sequence Introducer) removal."""

    def test_basic_ansi_colors(self) -> None:
        raw = "\x1b[31mRed Text\x1b[0m \x1b[1;32mBold Green\x1b[0m"
        assert strip_control_characters(raw) == "Red Text Bold Green"

    def test_rgb_24bit_and_256_colors(self) -> None:
        raw = "\x1b[38;2;255;128;0mOrange RGB\x1b[0m \x1b[48;5;196mRed BG\x1b[0m"
        assert strip_control_characters(raw) == "Orange RGB Red BG"

    def test_cursor_movement_sequences(self) -> None:
        raw = "\x1b[1ACursorUp\x1b[2BCursorDown\x1b[10CCursorRight\x1b[4DCursorLeft"
        assert strip_control_characters(raw) == "CursorUpCursorDownCursorRightCursorLeft"

    def test_screen_and_display_control(self) -> None:
        raw = "\x1b[2J\x1b[H\x1b[?25lHiddenCursor\x1b[?25hVisibleCursor"
        assert strip_control_characters(raw) == "HiddenCursorVisibleCursor"


class TestStripControlCharactersOsc:
    """Validate OSC (Operating System Command) sequence removal."""

    def test_osc_0_window_title_with_bel(self) -> None:
        raw = "\x1b]0;HACKED TITLE\x07Clean Text"
        assert strip_control_characters(raw) == "Clean Text"

    def test_osc_0_window_title_with_st(self) -> None:
        raw = "\x1b]0;HACKED TITLE\x1b\\Clean Text"
        assert strip_control_characters(raw) == "Clean Text"

    def test_osc_8_terminal_hyperlink_with_bel_and_st(self) -> None:
        bel_link = "\x1b]8;;https://evil.com\x07Click Here\x1b]8;;\x07"
        st_link = "\x1b]8;;https://evil.com\x1b\\Click Here\x1b]8;;\x1b\\"
        assert strip_control_characters(bel_link) == "Click Here"
        assert strip_control_characters(st_link) == "Click Here"

    def test_osc_52_clipboard_manipulation(self) -> None:
        raw_bel = "\x1b]52;c;BASE64DATA==\x07Target"
        raw_st = "\x1b]52;c;BASE64DATA==\x1b\\Target"
        assert strip_control_characters(raw_bel) == "Target"
        assert strip_control_characters(raw_st) == "Target"

    def test_truncated_osc_without_terminator(self) -> None:
        raw = "Safe Prefix \x1b]0;Truncated Incomplete OSC"
        assert strip_control_characters(raw) == "Safe Prefix "


class TestStripControlCharactersC0AndAscii:
    """Validate removal of ASCII C0 control characters and isolated ESC."""

    def test_isolated_escape_character(self) -> None:
        raw = "Escape \x1b alone in text"
        assert strip_control_characters(raw) == "Escape  alone in text"

    def test_carriage_return_neutralized(self) -> None:
        raw = "Line1\rLine2"
        assert strip_control_characters(raw) == "Line1Line2"
        assert "\r" not in strip_control_characters(raw)

    def test_null_byte_stripped(self) -> None:
        raw = "Data\x00With\x00Nulls"
        assert strip_control_characters(raw) == "DataWithNulls"
        assert "\x00" not in strip_control_characters(raw)

    def test_common_c0_controls_stripped(self) -> None:
        # 0x07 (BEL), 0x08 (BS), 0x0b (VT), 0x0c (FF), 0x7f (DEL)
        raw = "Alert\x07 Backspace\x08 VT\x0b FF\x0c DEL\x7f End"
        assert strip_control_characters(raw) == "Alert Backspace VT FF DEL End"

    def test_tabs_and_newlines_preserved(self) -> None:
        raw = "Line 1\n\tIndented Column"
        assert strip_control_characters(raw) == "Line 1\n\tIndented Column"


class TestStripControlCharactersUnicode:
    """Validate Unicode Bidirectional overrides, isolates, and normal characters."""

    def test_bidi_override_characters_stripped(self) -> None:
        # RLO (\u202e), LRO (\u202d), RLE (\u202b), LRE (\u202a), PDF (\u202c)
        rlo = "admin\u202egpj.exe"
        lro = "user\u202doverride"
        assert strip_control_characters(rlo) == "admingpj.exe"
        assert strip_control_characters(lro) == "useroverride"
        assert "\u202e" not in strip_control_characters(rlo)

    def test_bidi_isolate_and_marks_stripped(self) -> None:
        # LRI (\u2066), RLI (\u2067), FSI (\u2068), PDI (\u2069), LRM (\u200e), RLM (\u200f), ALM (\u061c)
        raw = "Text\u2066LRI\u2067RLI\u2068FSI\u2069PDI\u200eLRM\u200fRLM\u061cALM"
        assert strip_control_characters(raw) == "TextLRIRLIFSIPDILRMRLMALM"

    def test_normal_unicode_and_international_text_preserved(self) -> None:
        # Indonesian text with accents/symbols, accented Latin, Japanese, Emoji
        indonesian = "Domain ditemukan: sub-1.contoh.co.id (Peringatan: Status Aktif)"
        international = "Résumé café naïve — 日本語 — 🚀 Shield"
        assert strip_control_characters(indonesian) == indonesian
        assert strip_control_characters(international) == international


class TestNormalTextAndInputs:
    """Validate normal inputs, non-string types, and edge cases."""

    def test_alphanumeric_and_legitimate_symbols(self) -> None:
        raw = "Host: api-v2.example.com:8443?token=abc_123&env=prod#hash (OK!)"
        assert strip_control_characters(raw) == raw

    def test_urls_and_network_targets(self) -> None:
        urls = [
            "https://api.example.com/v1/users?id=10&active=true",
            "http://192.0.2.1:8080/metrics",
            "ftp://files.example.com/pub/data.tar.gz",
        ]
        for url in urls:
            assert strip_control_characters(url) == url

    def test_empty_string_and_whitespace(self) -> None:
        assert strip_control_characters("") == ""
        assert strip_control_characters("   ") == "   "

    def test_none_input_returns_empty_string(self) -> None:
        assert strip_control_characters(None) == ""

    def test_non_string_types_converted_safely(self) -> None:
        assert strip_control_characters(12345) == "12345"
        assert strip_control_characters(0) == "0"
        assert strip_control_characters(3.14159) == "3.14159"
        assert strip_control_characters(True) == "True"
        assert strip_control_characters(False) == "False"


class TestSanitizeTerminalTextAlias:
    """Validate sanitize_terminal_text behavior matches strip_control_characters."""

    def test_terminal_text_equivalence(self) -> None:
        sample = "\x1b[31mRed\x1b[0m \x1b]0;Title\x07Text\u202eReversed\r\x00"
        assert sanitize_terminal_text(sample) == strip_control_characters(sample)
        assert sanitize_terminal_text(sample) == "Red TextReversed"

    def test_terminal_text_non_string_and_none(self) -> None:
        assert sanitize_terminal_text(None) == ""
        assert sanitize_terminal_text(403) == "403"
        assert sanitize_terminal_text(0) == "0"


class TestControlSequenceRegex:
    """Validate direct regex compiled object matches expected sequences."""

    def test_control_sequence_regex_exported(self) -> None:
        assert hasattr(CONTROL_SEQUENCE, "sub")
        assert hasattr(CONTROL_SEQUENCE, "pattern")
        assert CONTROL_SEQUENCE.sub("", "\x1b[31mClean\x1b[0m") == "Clean"

