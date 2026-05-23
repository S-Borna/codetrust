"""Tests for the detection benchmark — the recall/false-positive proof artifact."""

from src.services.detection_benchmark import (
    CORPUS,
    BenchmarkReport,
    CategoryScore,
    format_report,
    run_detection_benchmark,
)


class TestCorpus:
    def test_corpus_has_vulnerable_and_safe_samples(self) -> None:
        vuln = [s for s in CORPUS if s.vulnerable]
        safe = [s for s in CORPUS if not s.vulnerable]
        # A benchmark without safe controls can't measure false positives.
        assert len(vuln) >= 10
        assert len(safe) >= 3

    def test_sample_ids_unique(self) -> None:
        ids = [s.sample_id for s in CORPUS]
        assert len(ids) == len(set(ids))


class TestBenchmarkRun:
    def test_runs_and_scores_honestly(self) -> None:
        report = run_detection_benchmark()
        assert report.vulnerable_total >= 10
        assert report.safe_total >= 3
        # Detected count can never exceed the number of vulnerable samples.
        assert 0 <= report.detected_total <= report.vulnerable_total
        # False positives can never exceed safe controls.
        assert 0 <= len(report.false_positives) <= report.safe_total
        assert 0.0 <= report.recall <= 1.0
        assert 0.0 <= report.false_positive_rate <= 1.0

    def test_detects_obvious_secret_and_eval(self) -> None:
        """Floor check: the engine must catch a hardcoded key and eval()."""
        report = run_detection_benchmark()
        # Every vulnerable sample in these high-signal categories should flag.
        for cat in ("secrets_exposure", "injection_attacks"):
            score = report.categories.get(cat)
            assert score is not None
            assert score.detected == score.vulnerable_total, score.misses

    def test_no_false_positives_on_safe_controls(self) -> None:
        """Safe, idiomatic code must not raise BLOCK findings."""
        report = run_detection_benchmark()
        assert report.false_positives == [], report.false_positives

    def test_report_dict_is_serializable(self) -> None:
        report = run_detection_benchmark()
        d = report.to_dict()
        assert "recall" in d
        assert "false_positive_rate" in d
        assert "by_category" in d

    def test_format_report_renders(self) -> None:
        out = format_report(run_detection_benchmark())
        assert "Detection Benchmark" in out
        assert "Recall" in out
        assert "False positives" in out


class TestScoringInvariants:
    def test_category_score_recall_zero_when_empty(self) -> None:
        assert CategoryScore(category="x").recall == 0.0

    def test_report_rates_zero_when_empty(self) -> None:
        empty = BenchmarkReport(categories={}, safe_total=0, false_positives=[])
        assert empty.recall == 0.0
        assert empty.false_positive_rate == 0.0
