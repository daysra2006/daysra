from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from daysra.knowledge.loader import KnowledgeBase, KnowledgeEntry
from daysra.store.db import FindingRecord

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_UNKNOWN_SEVERITY_RANK = 5


@dataclass(frozen=True)
class FallbackText:
    title: str
    meaning: str
    impact: str
    verify_steps: tuple[str, ...]
    concept: str


FALLBACKS: dict[str, FallbackText] = {
    "info": FallbackText(
        title="Temuan informasi",
        meaning=(
            "Pemindaian mencatat informasi yang berguna untuk memetakan permukaan "
            "serangan, bukan bukti kerentanan yang dapat dieksploitasi."
        ),
        impact=(
            "Dampak langsung biasanya rendah, tetapi informasi ini dapat membantu "
            "pihak yang tidak berwenang merencanakan langkah berikutnya."
        ),
        verify_steps=(
            "Tinjau konteks endpoint yang dilaporkan pada tabel temuan.",
            "Konfirmasi apakah informasi tersebut memang seharusnya dapat diakses publik.",
            "Bandingkan dengan kebijakan eksposur organisasi.",
        ),
        concept="Pemetaan permukaan serangan (attack surface) dan klasifikasi informasi.",
    ),
    "low": FallbackText(
        title="Temuan risiko rendah",
        meaning=(
            "Ada indikasi konfigurasi atau perilaku yang dapat melemahkan pertahanan, "
            "tetapi belum menunjukkan dampak langsung yang besar."
        ),
        impact=(
            "Bila dibiarkan, temuan risiko rendah dapat digabungkan dengan kelemahan "
            "lain untuk memperluas akses."
        ),
        verify_steps=(
            "Buka kembali endpoint yang sama di browser secara manual.",
            "Periksa header dan konfigurasi respons tanpa mengirim payload berbahaya.",
            "Catat apakah perilaku tersebut sesuai dengan kebijakan yang berlaku.",
        ),
        concept="Konfigurasi aman dan pertahanan berlapis (defense in depth).",
    ),
    "medium": FallbackText(
        title="Temuan risiko sedang",
        meaning=(
            "Ada indikasi kelemahan yang berpotensi dimanfaatkan pada kondisi tertentu, "
            "meskipun belum tentu dapat dieksploitasi secara langsung."
        ),
        impact=(
            "Dampak dapat berupa pembocoran informasi terbatas atau penurunan kontrol "
            "keamanan bila dibiarkan."
        ),
        verify_steps=(
            "Tinjau endpoint dan parameter yang dilaporkan.",
            "Lakukan verifikasi non-intrusif, misalnya memeriksa respons dan header.",
            "Konsultasikan dengan pemilik aplikasi sebelum pengujian lebih jauh.",
        ),
        concept="Manajemen kerentanan dan penilaian risiko.",
    ),
    "high": FallbackText(
        title="Temuan risiko tinggi",
        meaning=(
            "Indikasi kelemahan yang dapat berdampak signifikan bila terkonfirmasi dan "
            "dimanfaatkan oleh pihak yang tidak berwenang."
        ),
        impact=(
            "Potensi dampak mencakup akses tidak sah, pembocoran data, atau perubahan "
            "konfigurasi penting."
        ),
        verify_steps=(
            "Pastikan temuan berasal dari target yang sah dan berada dalam scope.",
            "Verifikasi secara non-intrusif melalui antarmuka yang sama di browser.",
            "Koordinasikan dengan pemilik sistem untuk penilaian lebih lanjut.",
        ),
        concept="Respons insiden dan pengujian penetrasi yang beretika.",
    ),
    "critical": FallbackText(
        title="Temuan risiko kritis",
        meaning=(
            "Indikasi kelemahan dengan potensi dampak sangat serius yang memerlukan "
            "perhatian segera."
        ),
        impact=(
            "Bila terkonfirmasi, kelemahan ini dapat menyebabkan kompromi sistem, "
            "kebocoran data besar, atau gangguan layanan."
        ),
        verify_steps=(
            "Hentikan pengujian aktif dan catat bukti yang sudah ada.",
            "Verifikasi hanya dengan cara non-intrusif dan sesuai izin scope.",
            "Hubungi pemilik sistem dan tim keamanan segera.",
        ),
        concept="Penanganan insiden dan prioritas remediasi.",
    ),
}


@dataclass(frozen=True)
class FindingExplanation:
    template_id: str
    name: str
    severity: str
    cve: tuple[str, ...]
    matched_at: tuple[str, ...]
    title: str
    meaning: str
    impact: str
    verify_steps: tuple[str, ...]
    concept: str
    is_fallback: bool


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity.strip().lower(), _UNKNOWN_SEVERITY_RANK)


def fallback_text_for(severity: str) -> FallbackText:
    return FALLBACKS.get(severity.strip().lower(), FALLBACKS["info"])


def _unique_in_order(values: Sequence[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return tuple(seen)


def _explanation_from_knowledge(
    entry: KnowledgeEntry,
    *,
    template_id: str,
    name: str,
    severity: str,
    cve: tuple[str, ...],
    matched_at: tuple[str, ...],
) -> FindingExplanation:
    return FindingExplanation(
        template_id=template_id,
        name=name,
        severity=severity,
        cve=cve,
        matched_at=matched_at,
        title=entry.title,
        meaning=entry.meaning,
        impact=entry.impact,
        verify_steps=entry.verify_steps,
        concept=entry.concept,
        is_fallback=False,
    )


def _explanation_from_fallback(
    fallback: FallbackText,
    *,
    template_id: str,
    name: str,
    severity: str,
    cve: tuple[str, ...],
    matched_at: tuple[str, ...],
) -> FindingExplanation:
    return FindingExplanation(
        template_id=template_id,
        name=name,
        severity=severity,
        cve=cve,
        matched_at=matched_at,
        title=fallback.title,
        meaning=fallback.meaning,
        impact=fallback.impact,
        verify_steps=fallback.verify_steps,
        concept=fallback.concept,
        is_fallback=True,
    )


def build_explanations(
    findings: Sequence[FindingRecord],
    knowledge: KnowledgeBase,
) -> list[FindingExplanation]:
    """Build one explanation per unique template_id, highest severity first.

    Facts supplied by the tool (template_id, name, severity, CVE, matched_at)
    are carried through unchanged. Only the narrative content comes from the
    knowledge base or the deterministic severity fallback.
    """
    groups: dict[str, list[FindingRecord]] = {}
    for finding in findings:
        groups.setdefault(finding.template_id, []).append(finding)

    explanations: list[FindingExplanation] = []
    for template_id, group in groups.items():
        representative = min(
            group,
            key=lambda finding: (
                severity_rank(finding.severity),
                finding.id,
            ),
        )
        cve = _unique_in_order([value for finding in group for value in finding.cve])
        matched_at = _unique_in_order([finding.matched_at for finding in group])

        entry = knowledge.get(template_id)
        if entry is not None:
            explanation = _explanation_from_knowledge(
                entry,
                template_id=template_id,
                name=representative.name,
                severity=representative.severity,
                cve=cve,
                matched_at=matched_at,
            )
        else:
            explanation = _explanation_from_fallback(
                fallback_text_for(representative.severity),
                template_id=template_id,
                name=representative.name,
                severity=representative.severity,
                cve=cve,
                matched_at=matched_at,
            )
        explanations.append(explanation)

    explanations.sort(key=lambda item: (severity_rank(item.severity), item.template_id))
    return explanations


__all__ = [
    "FALLBACKS",
    "SEVERITY_RANK",
    "FallbackText",
    "FindingExplanation",
    "build_explanations",
    "fallback_text_for",
    "severity_rank",
]
