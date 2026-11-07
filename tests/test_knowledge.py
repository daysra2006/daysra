from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from daysra.knowledge import (
    FALLBACKS,
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeError,
    build_explanations,
    load_knowledge_base,
)
from daysra.simple.summary import render_finding_explanations
from daysra.store.db import FindingRecord

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "schema" / "knowledge"


def _write_fixture(name: str, destination: Path) -> Path:
    destination.write_text((FIXTURE_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")
    return destination


def _finding(
    template_id: str,
    *,
    severity: str = "info",
    name: str = "Nama Temuan",
    matched_at: str = "https://sub.example.com/vuln",
    cve: list[str] | None = None,
    finding_id: str | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=finding_id or f"id-{template_id}-{matched_at}",
        hostname="sub.example.com",
        template_id=template_id,
        name=name,
        severity=severity,
        cve=list(cve or []),
        matched_at=matched_at,
        first_seen_run="run-1",
        last_seen_run="run-1",
        first_seen="2026-11-05T10:00:00Z",
        last_seen="2026-11-05T10:00:00Z",
    )


def _entry(
    template_id: str = "tech-detect",
    *,
    title: str = "Judul KB",
    meaning: str = "Arti dari temuan.",
    impact: str = "Dampak yang perlu dipahami.",
    verify_steps: tuple[str, ...] = ("Langkah verifikasi.",),
    concept: str = "Konsep yang dipelajari.",
) -> KnowledgeEntry:
    return KnowledgeEntry(
        template_id=template_id,
        title=title,
        meaning=meaning,
        impact=impact,
        verify_steps=verify_steps,
        concept=concept,
        lang="id",
        source=Path("knowledge/test.yaml"),
    )


def _render(findings: list[FindingRecord], knowledge: KnowledgeBase) -> str:
    console = Console(record=True, width=200, color_system=None)
    render_finding_explanations(findings, knowledge, console=console)
    return console.export_text()


class TestKnowledgeLoader:
    def test_existing_valid_fixtures_load(self, tmp_path: Path) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        _write_fixture("valid-sql-injection.json", knowledge_dir / "sql.yaml")
        _write_fixture("valid-missing-header.json", knowledge_dir / "headers.yaml")
        _write_fixture("valid-exposed-panel.json", knowledge_dir / "panel.yaml")

        knowledge = load_knowledge_base(knowledge_dir)

        assert set(knowledge.entries) == {
            "sql-injection-detect",
            "missing-security-headers",
            "exposed-admin-panel",
        }
        entry = knowledge.get("sql-injection-detect")
        assert entry is not None
        assert entry.title == "Indikasi SQL injection"
        assert entry.verify_steps == (
            "Tinjau parameter yang dilaporkan",
            "Konfirmasi secara aman di lingkungan legal",
        )
        assert entry.lang == "id"

    @pytest.mark.parametrize(
        ("fixture_name", "field"),
        [
            ("invalid-verify-steps-not-array.json", "verify_steps"),
            ("invalid-missing-lang.json", "lang"),
            ("invalid-extra-field.json", "unexpected"),
        ],
    )
    def test_existing_invalid_fixtures_are_rejected_with_file_and_field(
        self,
        tmp_path: Path,
        fixture_name: str,
        field: str,
    ) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        _write_fixture(fixture_name, knowledge_dir / "bad.yaml")

        with pytest.raises(KnowledgeError) as exc_info:
            load_knowledge_base(knowledge_dir)

        message = str(exc_info.value)
        assert "bad.yaml" in message
        assert field in message

    def test_broken_yaml_names_the_file(self, tmp_path: Path) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        (knowledge_dir / "broken.yaml").write_text("template_id: [unclosed\n", encoding="utf-8")

        with pytest.raises(KnowledgeError) as exc_info:
            load_knowledge_base(knowledge_dir)

        message = str(exc_info.value)
        assert "broken.yaml" in message
        assert "YAML" in message

    def test_duplicate_template_id_across_files_is_rejected(self, tmp_path: Path) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        content = (FIXTURE_DIR / "valid-sql-injection.json").read_text(encoding="utf-8")
        (knowledge_dir / "a.yaml").write_text(content, encoding="utf-8")
        (knowledge_dir / "b.yaml").write_text(content, encoding="utf-8")

        with pytest.raises(KnowledgeError) as exc_info:
            load_knowledge_base(knowledge_dir)

        message = str(exc_info.value)
        assert "a.yaml" in message
        assert "b.yaml" in message
        assert "template_id" in message
        assert "duplikat" in message

    def test_missing_directory_is_not_an_error(self, tmp_path: Path) -> None:
        knowledge = load_knowledge_base(tmp_path / "does-not-exist")

        assert len(knowledge) == 0
        assert not knowledge
        assert knowledge.get("anything") is None

    def test_empty_directory_is_not_an_error(self, tmp_path: Path) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()

        knowledge = load_knowledge_base(knowledge_dir)

        assert len(knowledge) == 0

    def test_file_may_contain_a_list_of_entries(self, tmp_path: Path) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        (knowledge_dir / "list.yaml").write_text(
            """
- template_id: first
  title: "Pertama"
  meaning: "Arti pertama."
  impact: "Dampak pertama."
  verify_steps: ["Langkah pertama."]
  concept: "Konsep pertama."
  lang: id
- template_id: second
  title: "Kedua"
  meaning: "Arti kedua."
  impact: "Dampak kedua."
  verify_steps: ["Langkah kedua."]
  concept: "Konsep kedua."
  lang: id
""",
            encoding="utf-8",
        )

        knowledge = load_knowledge_base(knowledge_dir)

        assert set(knowledge.entries) == {"first", "second"}

    def test_non_mapping_entry_is_rejected(self, tmp_path: Path) -> None:
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        (knowledge_dir / "list.yaml").write_text("- just-a-string\n", encoding="utf-8")

        with pytest.raises(KnowledgeError) as exc_info:
            load_knowledge_base(knowledge_dir)

        assert "objek YAML" in str(exc_info.value)

    def test_shipped_knowledge_base_is_valid(self) -> None:
        knowledge = load_knowledge_base(Path(__file__).resolve().parents[1] / "knowledge")

        assert len(knowledge) == 5
        assert knowledge.get("swagger-api") is not None
        assert knowledge.get("fingerprinthub-web-fingerprints") is None


class TestExplainer:
    def test_knowledge_entry_is_used_without_changing_tool_facts(self) -> None:
        entry = _entry(template_id="tech-detect")
        findings = [
            _finding(
                "tech-detect",
                severity="medium",
                name="Nama Asli dari Tool",
                matched_at="https://sub.example.com/a",
                cve=["CVE-2026-0001"],
            )
        ]

        explanation = build_explanations(findings, KnowledgeBase({"tech-detect": entry}))[0]

        assert explanation.is_fallback is False
        assert explanation.title == "Judul KB"
        assert explanation.meaning == "Arti dari temuan."
        assert explanation.impact == "Dampak yang perlu dipahami."
        assert explanation.verify_steps == ("Langkah verifikasi.",)
        assert explanation.concept == "Konsep yang dipelajari."
        # Facts from the tool are carried through unchanged.
        assert explanation.template_id == "tech-detect"
        assert explanation.name == "Nama Asli dari Tool"
        assert explanation.severity == "medium"
        assert explanation.cve == ("CVE-2026-0001",)
        assert explanation.matched_at == ("https://sub.example.com/a",)

    @pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
    def test_fallback_is_available_for_every_severity(self, severity: str) -> None:
        explanation = build_explanations(
            [_finding("unknown-template", severity=severity)], KnowledgeBase({})
        )[0]

        assert explanation.is_fallback is True
        assert explanation.severity == severity
        assert explanation.template_id == "unknown-template"
        assert explanation.title == FALLBACKS[severity].title
        assert explanation.meaning == FALLBACKS[severity].meaning
        assert explanation.verify_steps == FALLBACKS[severity].verify_steps

    def test_groups_by_template_id_and_orders_by_severity_then_template_id(self) -> None:
        findings = [
            _finding("t-info-b", severity="info", matched_at="https://a"),
            _finding("t-critical", severity="critical", matched_at="https://b"),
            _finding("t-info-a", severity="info", matched_at="https://c"),
            _finding("t-dup", severity="high", matched_at="https://d"),
            _finding("t-dup", severity="high", matched_at="https://e"),
        ]

        explanations = build_explanations(findings, KnowledgeBase({}))

        assert [item.template_id for item in explanations] == [
            "t-critical",
            "t-dup",
            "t-info-a",
            "t-info-b",
        ]
        duplicate = next(item for item in explanations if item.template_id == "t-dup")
        assert duplicate.matched_at == ("https://d", "https://e")

    def test_cve_values_are_preserved_and_deduplicated(self) -> None:
        findings = [
            _finding("t", severity="high", matched_at="https://a", cve=["CVE-1", "CVE-2"]),
            _finding("t", severity="high", matched_at="https://b", cve=["CVE-2", "CVE-3"]),
        ]

        explanation = build_explanations(findings, KnowledgeBase({}))[0]

        assert explanation.cve == ("CVE-1", "CVE-2", "CVE-3")


class TestExplanationDisplay:
    def test_blocks_are_ordered_by_severity_then_template_id(self) -> None:
        findings = [
            _finding("t-info", severity="info"),
            _finding("t-critical", severity="critical"),
            _finding("t-medium", severity="medium"),
        ]

        output = _render(findings, KnowledgeBase({}))

        positions = [
            output.index("Penjelasan: t-critical"),
            output.index("Penjelasan: t-medium"),
            output.index("Penjelasan: t-info"),
        ]
        assert positions == sorted(positions)

    def test_same_template_id_is_grouped_into_one_block(self) -> None:
        findings = [
            _finding("t-dup", severity="high", matched_at="https://sub.example.com/one"),
            _finding("t-dup", severity="high", matched_at="https://sub.example.com/two"),
        ]

        output = _render(findings, KnowledgeBase({}))

        assert output.count("Penjelasan: t-dup") == 1
        assert "https://sub.example.com/one" in output
        assert "https://sub.example.com/two" in output

    def test_at_most_five_matched_at_values_are_shown(self) -> None:
        findings = [
            _finding("t-many", severity="low", matched_at=f"https://sub.example.com/matched-{i}")
            for i in range(1, 8)
        ]

        output = _render(findings, KnowledgeBase({}))

        for index in range(1, 6):
            assert f"matched-{index}" in output
        assert "matched-6" not in output
        assert "matched-7" not in output
        assert "dan 2 lainnya" in output

    def test_fallback_is_labelled_and_knowledge_entries_are_not(self) -> None:
        fallback_output = _render([_finding("no-entry")], KnowledgeBase({}))
        knowledge_output = _render(
            [_finding("known")], KnowledgeBase({"known": _entry("known")})
        )

        assert "[fallback generik]" in fallback_output
        assert "[fallback generik]" not in knowledge_output
        assert "Judul KB" in knowledge_output

    def test_untrusted_fields_are_sanitized_and_markup_stays_literal(self) -> None:
        findings = [
            _finding(
                "t-evil",
                severity="high",
                name="\x1b[31m[bold red]Nama[/bold red]\x1b[0m",
                matched_at="https://sub.example.com/\x1b[32m[link]x[/link]",
            )
        ]
        entry = _entry(
            "t-evil",
            title="[bold red]Judul tidak dieksekusi[/bold red]",
            meaning="<b>Teks knowledge base</b>",
        )

        output = _render(findings, KnowledgeBase({"t-evil": entry}))

        assert "\x1b[31m" not in output
        assert "\x1b[32m" not in output
        assert "[bold red]Nama[/bold red]" in output
        assert "[link]x[/link]" in output
        assert "[bold red]Judul tidak dieksekusi[/bold red]" in output
        assert "<b>Teks knowledge base</b>" in output
