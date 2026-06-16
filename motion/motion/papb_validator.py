"""
PAPB action-flow validator.

This module assumes the traffic/action recognizer has already produced action
labels. It validates whether a label sequence follows the learned or configured
task transition graph.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import json
from pathlib import Path
import argparse
from datetime import datetime, timezone
import hashlib
from typing import Iterable


END_ACTION = "__END__"


@dataclass(frozen=True)
class PapbDecision:
    valid: bool
    status: str
    violations: list[dict[str, object]]
    matched_path: list[str]
    valid_prefix_length: int
    expected_next: list[str]
    terminal: bool
    action_count: int
    transition_count: int


@dataclass(frozen=True)
class PapbState:
    valid_next: set[str]
    matched_path: list[str]
    matched_indices: list[int]
    match_length: int
    terminal: bool
    state: str
    reason: str


@dataclass
class PapbValidator:
    adjacency: dict[str, list[str]] | None
    start_actions: list[str] | set[str] | None = None
    terminal_actions: list[str] | set[str] | None = None
    task_sequences: list[list[str]] | None = None
    max_repeats: dict[str, int] = field(default_factory=dict)
    critical_actions: list[str] | set[str] | None = None
    noncritical_actions: list[str] | set[str] | None = None
    embedding_centers: dict[str, list[float]] | None = None
    embedding_thresholds: dict[str, float] | None = None
    embedding_weight: float = 0.35
    transition_matrix: dict[str, dict[str, float]] | None = None
    forbidden_transitions: object = None
    transition_risk_threshold: float = 0.15
    max_edit_distance: int = 0
    max_error_ratio: float = 0.0
    end_action: str = END_ACTION
    allow_unknown_start: bool = False
    require_terminal: bool = False

    def __post_init__(self) -> None:
        normalized: dict[str, set[str]] = defaultdict(set)
        for action, next_actions in (self.adjacency or {}).items():
            normalized[action].update(next_actions)

        terminal_actions = set(self.terminal_actions or [])
        for action, next_actions in normalized.items():
            if self.end_action in next_actions:
                terminal_actions.add(action)

        for action in terminal_actions:
            normalized[action].add(self.end_action)

        object.__setattr__(
            self,
            "adjacency",
            {action: sorted(next_actions) for action, next_actions in normalized.items()},
        )
        object.__setattr__(self, "start_actions", set(self.start_actions or []))
        object.__setattr__(self, "terminal_actions", terminal_actions)
        object.__setattr__(
            self,
            "task_sequences",
            self._normalize_task_sequences(self.task_sequences or []),
        )
        object.__setattr__(self, "max_repeats", dict(self.max_repeats or {}))
        object.__setattr__(self, "critical_actions", set(self.critical_actions or []))
        object.__setattr__(self, "noncritical_actions", set(self.noncritical_actions or []))
        object.__setattr__(self, "embedding_centers", dict(self.embedding_centers or {}))
        object.__setattr__(self, "embedding_thresholds", dict(self.embedding_thresholds or {}))
        object.__setattr__(
            self,
            "transition_matrix",
            self._normalize_transition_matrix(self.transition_matrix),
        )
        object.__setattr__(
            self,
            "forbidden_transitions",
            self._normalize_forbidden(self.forbidden_transitions),
        )
        try:
            threshold = float(self.transition_risk_threshold)
        except (TypeError, ValueError):
            threshold = 0.15
        object.__setattr__(self, "transition_risk_threshold", threshold)

    @staticmethod
    def _normalize_transition_matrix(matrix: object) -> dict[str, dict[str, float]]:
        normalized: dict[str, dict[str, float]] = {}
        if not isinstance(matrix, dict):
            return normalized
        for source, targets in matrix.items():
            if not isinstance(targets, dict):
                continue
            row: dict[str, float] = {}
            for target, prob in targets.items():
                try:
                    row[str(target)] = float(prob)
                except (TypeError, ValueError):
                    continue
            normalized[str(source)] = row
        return normalized

    @staticmethod
    def _normalize_forbidden(rules: object) -> dict[tuple[str, str], dict[str, object]]:
        """Accept either a list of {from,to,rule,score} or a {"a->b": {...}} dict."""
        normalized: dict[tuple[str, str], dict[str, object]] = {}
        items: list[dict[str, object]] = []
        if isinstance(rules, list):
            items = [item for item in rules if isinstance(item, dict)]
        elif isinstance(rules, dict):
            for key, value in rules.items():
                entry = dict(value) if isinstance(value, dict) else {}
                if "->" in str(key):
                    src, _, dst = str(key).partition("->")
                    entry.setdefault("from", src.strip())
                    entry.setdefault("to", dst.strip())
                items.append(entry)
        for item in items:
            src = str(item.get("from", "")).strip()
            dst = str(item.get("to", "")).strip()
            if not src or not dst:
                continue
            normalized[(src, dst)] = {
                "rule": str(item.get("rule", "forbidden transition")),
                "score": float(item.get("score", 1.0)) if str(item.get("score", "")).strip() else 1.0,
            }
        return normalized

    @classmethod
    def from_task_sequences(
        cls,
        sequences: Iterable[Iterable[str]],
        *,
        max_repeats: dict[str, int] | None = None,
        critical_actions: list[str] | set[str] | None = None,
        noncritical_actions: list[str] | set[str] | None = None,
        embedding_centers: dict[str, list[float]] | None = None,
        embedding_thresholds: dict[str, float] | None = None,
        embedding_weight: float = 0.35,
        transition_matrix: dict[str, dict[str, float]] | None = None,
        forbidden_transitions: object = None,
        transition_risk_threshold: float = 0.15,
        max_edit_distance: int = 0,
        max_error_ratio: float = 0.0,
        end_action: str = END_ACTION,
        require_terminal: bool = False,
    ) -> "PapbValidator":
        adjacency: dict[str, set[str]] = defaultdict(set)
        start_actions: set[str] = set()
        terminal_actions: set[str] = set()
        task_sequences: list[list[str]] = []

        for raw_sequence in sequences:
            sequence = [action for action in raw_sequence if action]
            if not sequence:
                continue
            task_sequences.append(sequence)
            start_actions.add(sequence[0])
            terminal_actions.add(sequence[-1])
            for current_action, next_action in zip(sequence, sequence[1:]):
                adjacency[current_action].add(next_action)

        return cls(
            {action: sorted(next_actions) for action, next_actions in adjacency.items()},
            start_actions=start_actions,
            terminal_actions=terminal_actions,
            task_sequences=task_sequences,
            max_repeats=max_repeats or {},
            critical_actions=critical_actions or set(),
            noncritical_actions=noncritical_actions or set(),
            embedding_centers=embedding_centers or {},
            embedding_thresholds=embedding_thresholds or {},
            embedding_weight=embedding_weight,
            transition_matrix=transition_matrix or {},
            forbidden_transitions=forbidden_transitions,
            transition_risk_threshold=transition_risk_threshold,
            max_edit_distance=max_edit_distance,
            max_error_ratio=max_error_ratio,
            end_action=end_action,
            require_terminal=require_terminal,
        )

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        *,
        max_edit_distance: int | None = None,
        max_error_ratio: float | None = None,
        require_terminal: bool = True,
    ) -> "PapbValidator":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        normalized = _normalize_papb_dataset(data, path)
        return cls.from_task_sequences(
            normalized["normal_templates"],
            max_repeats=normalized["max_repeats"],
            critical_actions=normalized["critical_actions"],
            noncritical_actions=normalized["noncritical_actions"],
            embedding_centers=normalized["embedding_centers"],
            embedding_thresholds=normalized["embedding_thresholds"],
            embedding_weight=float(normalized["embedding_weight"]),
            transition_matrix=normalized["transition_matrix"],
            forbidden_transitions=normalized["forbidden_transitions"],
            transition_risk_threshold=float(normalized["transition_risk_threshold"]),
            max_edit_distance=(
                int(max_edit_distance)
                if max_edit_distance is not None
                else int(normalized["max_edit_distance"])
            ),
            max_error_ratio=(
                float(max_error_ratio)
                if max_error_ratio is not None
                else float(normalized["max_error_ratio"])
            ),
            require_terminal=require_terminal,
        )

    @classmethod
    def fit_from_records(
        cls,
        records: Iterable[object],
        *,
        max_edit_distance: int = 1,
        max_error_ratio: float = 0.0,
        critical_min_support: float = 0.8,
        noncritical_actions: list[str] | set[str] | None = None,
        repeat_margin: int = 0,
        embedding_threshold_margin: float = 3.0,
        min_embedding_threshold: float = 0.15,
        end_action: str = END_ACTION,
        require_terminal: bool = True,
    ) -> "PapbValidator":
        sequences: list[list[str]] = []
        action_items_by_sequence: list[list[dict[str, object]]] = []

        for record in records:
            raw_sequence = cls._extract_record_sequence(record)
            action_items = cls._normalize_action_items(raw_sequence)
            if not action_items:
                continue
            action_items_by_sequence.append(action_items)
            sequences.append([item["label"] for item in action_items])

        template_counts = Counter(tuple(sequence) for sequence in sequences)
        templates = [list(sequence) for sequence, _count in template_counts.most_common()]
        if not templates:
            raise ValueError("No normal training sequences were provided.")

        max_repeats = cls._learn_max_repeats(sequences, margin=repeat_margin)
        critical_actions = cls._learn_critical_actions(
            templates,
            min_support=critical_min_support,
            noncritical_actions=set(noncritical_actions or []),
        )
        centers, thresholds = cls._learn_embedding_stats(
            templates,
            action_items_by_sequence,
            threshold_margin=embedding_threshold_margin,
            min_threshold=min_embedding_threshold,
        )

        return cls.from_task_sequences(
            templates,
            max_repeats=max_repeats,
            critical_actions=critical_actions,
            noncritical_actions=noncritical_actions or set(),
            embedding_centers=centers,
            embedding_thresholds=thresholds,
            max_edit_distance=max_edit_distance,
            max_error_ratio=max_error_ratio,
            end_action=end_action,
            require_terminal=require_terminal,
        )

    @classmethod
    def fit_from_json(
        cls,
        path: str | Path,
        **kwargs,
    ) -> "PapbValidator":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        normalized = _normalize_papb_dataset(data, path)
        records = normalized["training_sequences"] or normalized["normal_templates"]
        return cls.fit_from_records(records, **kwargs)

    def predict_valid_next_actions(self, executed_sequence, start_actions=None):
        """
        Backward-compatible API.

        Returns: (valid_next, matched_actions, max_len). Prefer predict_next_state
        or validate_sequence for new code because they preserve path ordering and
        explain terminal/dead-end states.
        """
        state = self.predict_next_state(executed_sequence, start_actions=start_actions)
        return state.valid_next, set(state.matched_path), state.match_length

    def predict_next_state(self, executed_sequence, start_actions=None) -> PapbState:
        """
        Predict legal next actions from the best valid path in the history.

        Empty valid_next means no legal successor is known. It does not mean
        "allow anything".
        """
        starts = set(start_actions or self.start_actions)
        cleaned = self._clean_sequence(executed_sequence)
        if not cleaned:
            return PapbState(
                valid_next=starts,
                matched_path=[],
                matched_indices=[],
                match_length=0,
                terminal=False,
                state="START",
                reason="empty history",
            )

        matched_path, matched_indices = self._longest_valid_path(cleaned, starts)
        if not matched_path:
            return PapbState(
                valid_next=starts,
                matched_path=[],
                matched_indices=[],
                match_length=0,
                terminal=False,
                state="NO_MATCH",
                reason="history does not match any allowed start action",
            )

        last_action = matched_path[-1]
        valid_next = set(self.adjacency.get(last_action, []))
        terminal = self.end_action in valid_next or last_action in self.terminal_actions
        if terminal:
            valid_next.add(self.end_action)
            state = "TERMINAL"
            reason = "matched path reached a terminal action"
        elif valid_next:
            state = "IN_PROGRESS"
            reason = "matched path has legal successors"
        else:
            state = "DEAD_END"
            reason = "matched path has no legal successor"

        return PapbState(
            valid_next=valid_next,
            matched_path=matched_path,
            matched_indices=matched_indices,
            match_length=len(matched_path),
            terminal=terminal,
            state=state,
            reason=reason,
        )

    def validate_next_action(self, executed_sequence, action, start_actions=None) -> dict[str, object]:
        state = self.predict_next_state(executed_sequence, start_actions=start_actions)
        action = str(action).strip()
        valid_next = set(state.valid_next)
        is_valid = action in valid_next

        if state.state == "START":
            reason = "valid start action" if is_valid else "action is not an allowed start action"
        elif state.terminal and action != self.end_action:
            reason = "sequence already reached a terminal action"
        elif not valid_next:
            reason = "no legal successor is defined for the matched path"
        elif is_valid:
            reason = "valid next action"
        else:
            reason = f"illegal transition after '{state.matched_path[-1]}'"

        return {
            "is_valid": is_valid,
            "action": action,
            "expected_next": sorted(valid_next),
            "matched_path": state.matched_path,
            "matched_indices": state.matched_indices,
            "match_length": state.match_length,
            "terminal": state.terminal,
            "state": state.state,
            "reason": reason,
        }

    def validate_sequence(self, sequence: Iterable[object], *, require_terminal: bool | None = None) -> dict[str, object]:
        """
        Validate a complete action-label sequence.

        The returned dictionary is JSON-friendly and includes exact violation
        positions, expected actions, and the longest valid prefix.
        """
        action_items = self._normalize_action_items(sequence)
        actions = [item["label"] for item in action_items]
        require_terminal = self.require_terminal if require_terminal is None else require_terminal
        if self.task_sequences:
            return self._validate_sequence_by_templates(
                actions,
                action_items=action_items,
                require_terminal=require_terminal,
            )

        violations: list[dict[str, object]] = []
        matched_path: list[str] = []

        if not actions:
            return self._decision(
                valid=not self.start_actions,
                violations=[
                    {
                        "index": 0,
                        "previous": None,
                        "actual": None,
                        "expected": sorted(self.start_actions),
                        "reason": "empty sequence",
                    }
                ]
                if self.start_actions
                else [],
                matched_path=[],
                expected_next=sorted(self.start_actions),
                terminal=False,
                action_count=0,
            )

        repeat_violations = self._repeat_violations(actions)
        violations.extend(repeat_violations)

        first = actions[0]
        if self.start_actions and first not in self.start_actions and not self.allow_unknown_start:
            violations.append(
                {
                    "index": 0,
                    "previous": None,
                    "actual": first,
                    "expected": sorted(self.start_actions),
                    "reason": "action is not an allowed start action",
                }
            )
        else:
            matched_path.append(first)

        stopped_at_terminal = False
        for idx in range(1, len(actions)):
            previous = actions[idx - 1]
            actual = actions[idx]
            expected = set(self.adjacency.get(previous, []))
            previous_is_terminal = self.end_action in expected or previous in self.terminal_actions

            if previous_is_terminal and actual not in expected:
                stopped_at_terminal = True
                violations.append(
                    {
                        "index": idx,
                        "previous": previous,
                        "actual": actual,
                        "expected": [self.end_action],
                        "reason": "extra action appears after a terminal action",
                    }
                )
                continue

            if actual not in expected:
                violations.append(
                    {
                        "index": idx,
                        "previous": previous,
                        "actual": actual,
                        "expected": sorted(expected),
                        "reason": f"illegal transition: {previous} -> {actual}",
                    }
                )
                continue

            if not violations:
                matched_path.append(actual)

        last_action = actions[-1]
        expected_next = set(self.adjacency.get(last_action, []))
        terminal = self.end_action in expected_next or last_action in self.terminal_actions
        if terminal:
            expected_next.add(self.end_action)

        if require_terminal and not terminal and not stopped_at_terminal:
            violations.append(
                {
                    "index": len(actions),
                    "previous": last_action,
                    "actual": self.end_action,
                    "expected": [self.end_action],
                    "reason": "sequence ended before reaching a terminal action",
                }
            )

        return self._decision(
            valid=not violations,
            violations=violations,
            matched_path=matched_path,
            expected_next=sorted(expected_next),
            terminal=terminal or stopped_at_terminal,
            action_count=len(actions),
        )

    def explain_sequence(self, sequence: Iterable[str]) -> str:
        result = self.validate_sequence(sequence)
        if result["valid"]:
            return "Sequence is valid: " + " -> ".join(result["matched_path"])

        lines = ["Sequence is invalid."]
        for violation in result["violations"]:
            lines.append(
                f"- index {violation['index']}: {violation['reason']} "
                f"(actual={violation['actual']}, expected={violation['expected']})"
            )
        return "\n".join(lines)

    def _decision(
        self,
        *,
        valid: bool,
        violations: list[dict[str, object]],
        matched_path: list[str],
        expected_next: list[str],
        terminal: bool,
        action_count: int,
        status: str | None = None,
        template_match: dict[str, object] | None = None,
        candidate_matches: list[dict[str, object]] | None = None,
        transition_check: dict[str, object] | None = None,
    ) -> dict[str, object]:
        transition_count = max(0, action_count - 1)
        result = {
            "valid": valid,
            "status": status or ("NORMAL" if valid else "ANOMALY"),
            "violations": violations,
            "matched_path": matched_path,
            "valid_prefix_length": len(matched_path),
            "expected_next": expected_next,
            "terminal": terminal,
            "action_count": action_count,
            "transition_count": transition_count,
        }
        if template_match is not None:
            result["template_match"] = template_match
        if candidate_matches is not None:
            result["candidate_matches"] = candidate_matches
        if transition_check is not None:
            result["transition_check"] = transition_check
        return result

    def _longest_valid_path(
        self,
        actions: list[str],
        start_actions: set[str],
    ) -> tuple[list[str], list[int]]:
        dp = [0] * len(actions)
        paths: list[list[str]] = [[] for _ in actions]
        indices: list[list[int]] = [[] for _ in actions]

        for i, action in enumerate(actions):
            if not start_actions or action in start_actions or self.allow_unknown_start:
                dp[i] = 1
                paths[i] = [action]
                indices[i] = [i]

            for j in range(i):
                previous = actions[j]
                if dp[j] and action in self.adjacency.get(previous, []):
                    candidate_len = dp[j] + 1
                    if candidate_len > dp[i]:
                        dp[i] = candidate_len
                        paths[i] = paths[j] + [action]
                        indices[i] = indices[j] + [i]

        if not dp or max(dp) == 0:
            return [], []

        best_idx = max(
            range(len(actions)),
            key=lambda idx: (dp[idx], indices[idx][-1] if indices[idx] else -1),
        )
        return paths[best_idx], indices[best_idx]

    def _repeat_violations(self, actions: list[str]) -> list[dict[str, object]]:
        violations: list[dict[str, object]] = []
        if not actions:
            return violations

        current = actions[0]
        run_start = 0
        run_length = 1
        for idx, action in enumerate(actions[1:], start=1):
            if action == current:
                run_length += 1
            else:
                violations.extend(self._check_repeat_run(current, run_start, run_length))
                current = action
                run_start = idx
                run_length = 1
        violations.extend(self._check_repeat_run(current, run_start, run_length))
        return violations

    def _check_repeat_run(
        self,
        action: str,
        run_start: int,
        run_length: int,
    ) -> list[dict[str, object]]:
        max_repeat = self.max_repeats.get(action)
        if max_repeat is None or run_length <= max_repeat:
            return []

        return [
            {
                "index": run_start + max_repeat,
                "previous": action,
                "actual": action,
                "expected": [f"repeat <= {max_repeat}"],
                "reason": f"action '{action}' repeats {run_length} times, max allowed is {max_repeat}",
            }
        ]

    @staticmethod
    def _clean_sequence(sequence: Iterable[str]) -> list[str]:
        return [str(action).strip() for action in sequence if str(action).strip()]

    @staticmethod
    def _normalize_action_items(sequence: Iterable[object]) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        for raw in sequence:
            if isinstance(raw, dict):
                label = str(raw.get("label", "")).strip()
                if not label:
                    continue
                item = dict(raw)
                item["label"] = label
                items.append(item)
            else:
                label = str(raw).strip()
                if label:
                    items.append({"label": label})
        return items

    @staticmethod
    def _normalize_task_sequences(sequences: Iterable[Iterable[str]]) -> list[list[str]]:
        normalized: list[list[str]] = []
        for sequence in sequences:
            cleaned = [str(action).strip() for action in sequence if str(action).strip()]
            if cleaned:
                normalized.append(cleaned)
        return normalized

    def _validate_sequence_by_templates(
        self,
        actions: list[str],
        *,
        action_items: list[dict[str, object]] | None = None,
        require_terminal: bool,
    ) -> dict[str, object]:
        action_items = action_items or [{"label": action} for action in actions]
        repeat_violations = self._repeat_violations(actions)
        if not actions:
            return self._decision(
                valid=False,
                violations=[
                    {
                        "index": 0,
                        "previous": None,
                        "actual": None,
                        "expected": ["one of the configured task templates"],
                        "reason": "empty sequence",
                    }
                ],
                matched_path=[],
                expected_next=sorted(self.start_actions),
                terminal=False,
                action_count=0,
                template_match=None,
            )

        template_matches = [
            self._align_to_template(actions, template, template_idx)
            for template_idx, template in enumerate(self.task_sequences or [], start=1)
        ]
        best = min(
            template_matches,
            key=lambda item: (
                item["edit_distance"],
                item["error_ratio"],
                -item["matched_count"],
                item["template_index"],
            ),
        )
        ranked_matches = sorted(
            template_matches,
            key=lambda item: (
                item["edit_distance"],
                item["error_ratio"],
                -item["matched_count"],
                item["template_index"],
            ),
        )

        allowed_distance = max(
            int(self.max_edit_distance),
            int(self.max_error_ratio * max(len(actions), len(best["template"]))),
        )
        within_tolerance = best["edit_distance"] <= allowed_distance
        is_exact = best["edit_distance"] == 0
        hard_violations = [
            violation
            for violation in best["violations"]
            if violation.get("expected") == [self.end_action]
            or any(expected in self.critical_actions for expected in violation.get("expected", []))
        ]
        soft_violations = [
            violation
            for violation in best["violations"]
            if violation not in hard_violations
        ]
        tolerated_violations = [
            violation
            for violation in soft_violations
            if any(expected in self.noncritical_actions for expected in violation.get("expected", []))
        ]
        embedding_result = self._embedding_match(best, action_items)
        if embedding_result["violations"]:
            hard_violations.extend(embedding_result["violations"])
        transition_result = self._transition_analysis(actions)
        forbidden_violations = transition_result.get("violations", [])
        if forbidden_violations:
            hard_violations.extend(forbidden_violations)
        valid = (
            (is_exact and not hard_violations)
            or (
                within_tolerance
                and bool(tolerated_violations)
                and len(tolerated_violations) == len(best["violations"])
                and not hard_violations
            )
        )

        violations = list(repeat_violations)
        if not valid:
            violations.extend(best["violations"])
            violations.extend(embedding_result["violations"])
            violations.extend(forbidden_violations)
        elif repeat_violations:
            valid = False
        status = "ANOMALY"
        if valid and is_exact:
            status = "NORMAL"
        elif valid:
            status = "NORMAL_WITH_TOLERANCE"

        trailing_missing = [
            violation
            for violation in best["violations"]
            if violation.get("actual") is None and violation.get("index") == len(actions)
        ]
        if require_terminal and valid and trailing_missing:
            next_expected = [
                expected
                for violation in trailing_missing
                for expected in violation.get("expected", [])
            ]
            violations.append(
                {
                    "index": len(actions),
                    "previous": actions[-1] if actions else None,
                    "actual": self.end_action,
                    "expected": next_expected,
                    "reason": "sequence ended before completing the matched task template",
                }
            )
            valid = False
            status = "ANOMALY"

        graph_check = self._check_graph_plausibility(actions)
        if (
            not valid
            and not hard_violations
            and not repeat_violations
            and graph_check["plausible"]
        ):
            status = "UNKNOWN_VALIDITY"
            violations = [
                {
                    "index": None,
                    "previous": None,
                    "actual": actions,
                    "expected": ["manual review"],
                    "reason": (
                        "No known complete template matched within tolerance, "
                        "but the action transitions are plausible in the learned task graph."
                    ),
                }
            ]

        expected_next = []
        if best["matched_prefix_length"] < len(best["template"]):
            expected_next = [best["template"][best["matched_prefix_length"]]]
        else:
            expected_next = [self.end_action]

        return self._decision(
            valid=valid,
            violations=violations,
            matched_path=best["matched_path"],
            expected_next=expected_next,
            terminal=best["matched_prefix_length"] >= len(best["template"]),
            action_count=len(actions),
            status=status,
            template_match={
                "template_index": best["template_index"],
                "template": best["template"],
                "edit_distance": best["edit_distance"],
                "error_ratio": best["error_ratio"],
                "within_tolerance": within_tolerance,
                "allowed_distance": allowed_distance,
                "operations": best["operations"],
                "embedding": embedding_result,
                "graph_check": graph_check,
                "transition_check": transition_result,
            },
            candidate_matches=[
                self._summarize_template_match(item, allowed_distance)
                for item in ranked_matches[:3]
            ],
            transition_check=transition_result,
        )

    def _align_to_template(
        self,
        actions: list[str],
        template: list[str],
        template_index: int,
    ) -> dict[str, object]:
        n = len(actions)
        m = len(template)
        dp = [[0] * (m + 1) for _ in range(n + 1)]
        back = [[""] * (m + 1) for _ in range(n + 1)]

        for i in range(1, n + 1):
            dp[i][0] = i
            back[i][0] = "extra"
        for j in range(1, m + 1):
            dp[0][j] = j
            back[0][j] = "missing"

        for i in range(1, n + 1):
            for j in range(1, m + 1):
                if actions[i - 1] == template[j - 1]:
                    choices = [(dp[i - 1][j - 1], "match")]
                else:
                    choices = [(dp[i - 1][j - 1] + 1, "substitute")]
                choices.extend(
                    [
                        (dp[i - 1][j] + 1, "extra"),
                        (dp[i][j - 1] + 1, "missing"),
                    ]
                )
                cost, op = min(choices, key=lambda item: item[0])
                dp[i][j] = cost
                back[i][j] = op

        operations = []
        violations = []
        matched_path_reversed = []
        i, j = n, m
        while i > 0 or j > 0:
            op = back[i][j]
            if op == "match":
                operations.append(
                    {
                        "op": "match",
                        "action_index": i - 1,
                        "template_index": j - 1,
                        "actual": actions[i - 1],
                        "expected": template[j - 1],
                    }
                )
                matched_path_reversed.append(actions[i - 1])
                i -= 1
                j -= 1
            elif op == "substitute":
                operations.append(
                    {
                        "op": "substitute",
                        "action_index": i - 1,
                        "template_index": j - 1,
                        "actual": actions[i - 1],
                        "expected": template[j - 1],
                    }
                )
                violations.append(
                    {
                        "index": i - 1,
                        "previous": actions[i - 2] if i >= 2 else None,
                        "actual": actions[i - 1],
                        "expected": [template[j - 1]],
                        "reason": f"unexpected action '{actions[i - 1]}', expected '{template[j - 1]}'",
                    }
                )
                i -= 1
                j -= 1
            elif op == "extra":
                operations.append(
                    {
                        "op": "extra",
                        "action_index": i - 1,
                        "template_index": j,
                        "actual": actions[i - 1],
                        "expected": template[j] if j < m else self.end_action,
                    }
                )
                violations.append(
                    {
                        "index": i - 1,
                        "previous": actions[i - 2] if i >= 2 else None,
                        "actual": actions[i - 1],
                        "expected": [template[j] if j < m else self.end_action],
                        "reason": f"extra action '{actions[i - 1]}' is not part of the matched task template",
                    }
                )
                i -= 1
            else:
                operations.append(
                    {
                        "op": "missing",
                        "action_index": i,
                        "template_index": j - 1,
                        "actual": None,
                        "expected": template[j - 1],
                    }
                )
                violations.append(
                    {
                        "index": i,
                        "previous": actions[i - 1] if i >= 1 else None,
                        "actual": None,
                        "expected": [template[j - 1]],
                        "reason": f"missing expected action '{template[j - 1]}'",
                    }
                )
                j -= 1

        operations.reverse()
        violations.reverse()
        matched_path = list(reversed(matched_path_reversed))
        matched_prefix_length = 0
        for left, right in zip(actions, template):
            if left != right:
                break
            matched_prefix_length += 1

        edit_distance = int(dp[n][m])
        denom = max(n, m, 1)
        return {
            "template_index": template_index,
            "template": template,
            "edit_distance": edit_distance,
            "error_ratio": edit_distance / denom,
            "matched_count": len(matched_path),
            "matched_path": matched_path,
            "matched_prefix_length": matched_prefix_length,
            "operations": operations,
            "violations": violations,
        }

    def _summarize_template_match(
        self,
        match: dict[str, object],
        allowed_distance: int,
    ) -> dict[str, object]:
        template = list(match["template"])
        prefix_len = int(match["matched_prefix_length"])
        next_action = template[prefix_len] if prefix_len < len(template) else self.end_action
        edit_distance = int(match["edit_distance"])
        return {
            "template_index": match["template_index"],
                "template": template,
                "edit_distance": edit_distance,
                "error_ratio": match["error_ratio"],
                "within_tolerance": edit_distance <= allowed_distance,
                "next_expected": next_action,
                "matched_count": match["matched_count"],
                "critical_mismatch": any(
                    expected in self.critical_actions
                    for violation in match.get("violations", [])
                    for expected in violation.get("expected", [])
                ),
            }

    def _check_graph_plausibility(self, actions: list[str]) -> dict[str, object]:
        if not actions:
            return {
                "plausible": False,
                "reason": "empty sequence",
                "invalid_transitions": [],
            }
        invalid = []
        if self.start_actions and actions[0] not in self.start_actions:
            invalid.append(
                {
                    "index": 0,
                    "previous": None,
                    "actual": actions[0],
                    "expected": sorted(self.start_actions),
                    "reason": "invalid start action",
                }
            )

        for idx, (previous, actual) in enumerate(zip(actions, actions[1:]), start=1):
            allowed = set(self.adjacency.get(previous, []))
            if actual not in allowed:
                invalid.append(
                    {
                        "index": idx,
                        "previous": previous,
                        "actual": actual,
                        "expected": sorted(allowed),
                        "reason": f"transition {previous} -> {actual} is not in the learned task graph",
                    }
                )

        return {
            "plausible": not invalid,
            "reason": "all observed transitions are in the learned task graph"
            if not invalid
            else "one or more transitions are not in the learned task graph",
            "invalid_transitions": invalid,
        }

    def _transition_analysis(self, actions: list[str]) -> dict[str, object]:
        """
        Gate ④: Markov transition check.

        - Forbidden transitions (state-constraint rules) are HARD violations → ANOMALY.
        - Every consecutive pair gets a risk score (risk = 1 - P(next|current)) for
          explanation only; it does not by itself fail the sequence.
        """
        enabled = bool(self.transition_matrix or self.forbidden_transitions)
        if not enabled or len(actions) < 2:
            return {"enabled": enabled, "threshold": self.transition_risk_threshold, "transitions": [], "violations": []}

        transitions: list[dict[str, object]] = []
        violations: list[dict[str, object]] = []
        risks: list[float] = []

        for idx in range(1, len(actions)):
            previous = actions[idx - 1]
            actual = actions[idx]
            row = self.transition_matrix.get(previous, {})
            has_row = bool(row)
            seen = actual in row
            prob = float(row.get(actual, 0.0))
            risk = round(1.0 - prob, 4)
            forbidden = self.forbidden_transitions.get((previous, actual))

            if forbidden:
                level = "forbidden"
            elif not has_row:
                level = "unknown"  # no statistics learned for the source action
            elif not seen:
                level = "unseen"   # source seen, but this transition never observed
            elif prob >= 0.25:
                level = "high"     # high-confidence normal transition
            elif prob >= 0.10:
                level = "medium"
            else:
                level = "low"      # rare transition, worth attention

            entry = {
                "index": idx,
                "previous": previous,
                "actual": actual,
                "probability": round(prob, 4),
                "risk": risk,
                "level": level,
            }
            if forbidden:
                entry["rule"] = forbidden["rule"]
                entry["rule_score"] = forbidden["score"]
            transitions.append(entry)
            if has_row or forbidden:
                risks.append(risk)

            if forbidden:
                allowed = sorted(row.keys()) if has_row else []
                violations.append(
                    {
                        "index": idx,
                        "previous": previous,
                        "actual": actual,
                        "expected": allowed,
                        "reason": (
                            f"forbidden transition '{previous} -> {actual}' "
                            f"(rule: {forbidden['rule']}, score {forbidden['score']:.2f})"
                        ),
                        "hard": True,
                    }
                )

        mean_risk = round(sum(risks) / len(risks), 4) if risks else 0.0
        max_risk = round(max(risks), 4) if risks else 0.0
        return {
            "enabled": True,
            "threshold": self.transition_risk_threshold,
            "transitions": transitions,
            "violations": violations,
            "mean_risk": mean_risk,
            "max_risk": max_risk,
            "forbidden_count": len(violations),
        }

    def _embedding_match(
        self,
        match: dict[str, object],
        action_items: list[dict[str, object]],
    ) -> dict[str, object]:
        distances = []
        violations = []
        total = 0.0
        used = 0

        for operation in match.get("operations", []):
            if operation.get("op") != "match":
                continue
            action_index = int(operation["action_index"])
            template_index = int(operation["template_index"])
            if action_index < 0 or action_index >= len(action_items):
                continue
            embedding = action_items[action_index].get("embedding")
            if embedding is None:
                continue

            expected = str(operation["expected"])
            center_key = self._center_key(
                int(match["template_index"]),
                template_index,
                expected,
            )
            center = self.embedding_centers.get(center_key) or self.embedding_centers.get(expected)
            if center is None:
                continue

            distance = self._euclidean_distance(embedding, center)
            threshold = float(
                self.embedding_thresholds.get(
                    center_key,
                    self.embedding_thresholds.get(expected, 1.0),
                )
            )
            item = {
                "action_index": action_index,
                "template_position": template_index,
                "action": expected,
                "center_key": center_key,
                "distance": distance,
                "threshold": threshold,
                "passed": distance <= threshold,
            }
            distances.append(item)
            total += min(distance / max(threshold, 1e-9), 3.0)
            used += 1
            if distance > threshold:
                violations.append(
                    {
                        "index": action_index,
                        "previous": action_items[action_index - 1]["label"] if action_index else None,
                        "actual": expected,
                        "expected": [f"embedding distance <= {threshold:.3f}"],
                        "reason": (
                            f"embedding mismatch for '{expected}': "
                            f"distance {distance:.3f} > threshold {threshold:.3f}"
                        ),
                    }
                )

        return {
            "enabled": bool(self.embedding_centers),
            "checked": used,
            "mean_normalized_distance": total / max(used, 1),
            "weight": self.embedding_weight,
            "distances": distances,
            "violations": violations,
        }

    @staticmethod
    def _center_key(template_index: int, template_position: int, action: str) -> str:
        return f"template:{template_index}:pos:{template_position}:action:{action}"

    @staticmethod
    def _euclidean_distance(left: object, right: object) -> float:
        left_values = [float(value) for value in left]
        right_values = [float(value) for value in right]
        if len(left_values) != len(right_values):
            raise ValueError(
                f"Embedding dimension mismatch: {len(left_values)} != {len(right_values)}"
            )
        return sum((a - b) ** 2 for a, b in zip(left_values, right_values)) ** 0.5

    def evaluate_dataset(
        self,
        records: Iterable[dict[str, object]],
    ) -> dict[str, object]:
        rows = []
        correct = 0
        total = 0
        for record in records:
            expected = str(record.get("expected_status", "")).strip()
            sequence = record.get("actions", record.get("sequence", []))
            result = self.validate_sequence(sequence)
            predicted = str(result["status"])
            ok = predicted == expected
            correct += int(ok)
            total += 1
            rows.append(
                {
                    "id": record.get("id", ""),
                    "expected_status": expected,
                    "predicted_status": predicted,
                    "correct": ok,
                    "sequence": sequence,
                    "violations": result.get("violations", []),
                    "template_match": result.get("template_match", {}),
                }
            )
        return {
            "accuracy": correct / max(total, 1),
            "correct": correct,
            "total": total,
            "rows": rows,
        }

    def evaluate_json(self, path: str | Path) -> dict[str, object]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        normalized = _normalize_papb_dataset(data, path)
        records = _map_evaluation_sequences(
            data.get("evaluation_sequences", []),
            normalized["action_map"],
        )
        return self.evaluate_dataset(records)

    def to_model_dict(self) -> dict[str, object]:
        return {
            "normal_templates": self.task_sequences,
            "max_repeats": self.max_repeats,
            "critical_actions": sorted(self.critical_actions),
            "noncritical_actions": sorted(self.noncritical_actions),
            "embedding_centers": self.embedding_centers,
            "embedding_thresholds": self.embedding_thresholds,
            "embedding_weight": self.embedding_weight,
            "transition_matrix": self.transition_matrix,
            "forbidden_transitions": [
                {"from": src, "to": dst, "rule": meta["rule"], "score": meta["score"]}
                for (src, dst), meta in self.forbidden_transitions.items()
            ],
            "transition_risk_threshold": self.transition_risk_threshold,
            "max_edit_distance": self.max_edit_distance,
            "max_error_ratio": self.max_error_ratio,
            "end_action": self.end_action,
            "require_terminal": self.require_terminal,
        }

    def save_model(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_model_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _extract_record_sequence(record: object) -> Iterable[object]:
        if isinstance(record, dict):
            return record.get("actions", record.get("sequence", []))
        return record

    @staticmethod
    def _learn_max_repeats(sequences: list[list[str]], *, margin: int) -> dict[str, int]:
        learned: dict[str, int] = {}
        for sequence in sequences:
            if not sequence:
                continue
            current = sequence[0]
            run = 1
            for action in sequence[1:]:
                if action == current:
                    run += 1
                else:
                    learned[current] = max(learned.get(current, 0), run + margin)
                    current = action
                    run = 1
            learned[current] = max(learned.get(current, 0), run + margin)
        return learned

    @staticmethod
    def _learn_critical_actions(
        templates: list[list[str]],
        *,
        min_support: float,
        noncritical_actions: set[str],
    ) -> set[str]:
        if not templates:
            return set()
        counts = Counter()
        for template in templates:
            counts.update(set(template))
        total = len(templates)
        learned = {
            action
            for action, count in counts.items()
            if count / total >= min_support
        }
        if min_support <= 0:
            learned = {action for template in templates for action in template}
        return learned - noncritical_actions

    @classmethod
    def _learn_embedding_stats(
        cls,
        templates: list[list[str]],
        action_items_by_sequence: list[list[dict[str, object]]],
        *,
        threshold_margin: float,
        min_threshold: float,
    ) -> tuple[dict[str, list[float]], dict[str, float]]:
        grouped: dict[str, list[list[float]]] = defaultdict(list)
        template_lookup = {tuple(template): idx for idx, template in enumerate(templates, start=1)}

        for action_items in action_items_by_sequence:
            labels = [item["label"] for item in action_items]
            template_idx = template_lookup.get(tuple(labels))
            if template_idx is None:
                continue
            for pos, item in enumerate(action_items):
                embedding = item.get("embedding")
                if embedding is None:
                    continue
                action = str(item["label"])
                grouped[cls._center_key(template_idx, pos, action)].append(
                    [float(value) for value in embedding]
                )

        centers: dict[str, list[float]] = {}
        thresholds: dict[str, float] = {}
        for key, vectors in grouped.items():
            center = cls._mean_vector(vectors)
            distances = [cls._euclidean_distance(vector, center) for vector in vectors]
            mean_distance = sum(distances) / max(len(distances), 1)
            variance = sum((distance - mean_distance) ** 2 for distance in distances) / max(len(distances), 1)
            threshold = max(min_threshold, mean_distance + threshold_margin * (variance ** 0.5))
            centers[key] = [round(value, 6) for value in center]
            thresholds[key] = round(threshold, 6)
        return centers, thresholds

    @staticmethod
    def _mean_vector(vectors: list[list[float]]) -> list[float]:
        if not vectors:
            return []
        dims = len(vectors[0])
        return [
            sum(vector[idx] for vector in vectors) / len(vectors)
            for idx in range(dims)
        ]

    def transition_counts(self, sequence: Iterable[str]) -> dict[tuple[str, str], int]:
        actions = self._clean_sequence(sequence)
        return dict(Counter(zip(actions, actions[1:])))


def _resolve_action_map(data: object, source_path: str | Path | None) -> dict[str, str]:
    action_map = {}
    if isinstance(data, dict):
        action_map = data.get("actions") or data.get("action_map") or {}

    if not action_map and source_path:
        candidate = Path(source_path).with_name("action_map.json")
        if candidate.exists():
            action_map = json.loads(candidate.read_text(encoding="utf-8"))

    return {
        str(key).strip(): str(value).strip()
        for key, value in (action_map or {}).items()
        if str(value).strip()
    }


def _coerce_action_label(value: object, action_map: dict[str, str]) -> str:
    label = str(value).strip()
    if not label:
        return ""

    mapped = action_map.get(label)
    if mapped is not None:
        return str(mapped).strip()

    if action_map:
        try:
            numeric_key = str(int(float(label)))
        except ValueError:
            numeric_key = ""
        if numeric_key:
            mapped = action_map.get(numeric_key)
            if mapped is not None:
                return str(mapped).strip()

    return label


def _map_action_list(values: Iterable[object], action_map: dict[str, str]) -> list[str]:
    mapped: list[str] = []
    for value in values:
        label = _coerce_action_label(value, action_map)
        if label:
            mapped.append(label)
    return mapped


def _map_action_dict_keys(values: dict[object, object], action_map: dict[str, str]) -> dict[str, object]:
    mapped: dict[str, object] = {}
    for key, value in (values or {}).items():
        mapped_key = _coerce_action_label(key, action_map)
        if mapped_key:
            mapped[mapped_key] = value
    return mapped


def _extract_sequences_from_data(data: object) -> list[Iterable[object]]:
    raw: list[object]
    if isinstance(data, dict):
        raw = (
            data.get("training_sequences")
            or data.get("normal_sequences")
            or data.get("normal_templates")
            or data.get("sequences")
            or []
        )
    elif isinstance(data, list):
        raw = data
    else:
        raw = []

    sequences: list[Iterable[object]] = []
    for entry in raw:
        if isinstance(entry, dict):
            sequence = entry.get("actions", entry.get("sequence", []))
        else:
            sequence = entry
        if sequence:
            sequences.append(sequence)
    return sequences


def _map_sequence_items(sequence: Iterable[object], action_map: dict[str, str]) -> list[object]:
    mapped: list[object] = []
    for item in sequence:
        if isinstance(item, dict):
            label = item.get("label", "")
            mapped_label = _coerce_action_label(label, action_map)
            if not mapped_label:
                continue
            new_item = dict(item)
            new_item["label"] = mapped_label
            mapped.append(new_item)
        else:
            mapped_label = _coerce_action_label(item, action_map)
            if mapped_label:
                mapped.append(mapped_label)
    return mapped


def _sequence_labels(sequence: Iterable[object]) -> list[str]:
    labels: list[str] = []
    for item in sequence:
        if isinstance(item, dict):
            label = str(item.get("label", "")).strip()
        else:
            label = str(item).strip()
        if label:
            labels.append(label)
    return labels


def _map_transition_matrix(matrix: object, action_map: dict[str, str]) -> dict[str, dict[str, float]]:
    """Map a transition matrix to action labels (keys may be numeric ids or labels)."""
    mapped: dict[str, dict[str, float]] = {}
    if not isinstance(matrix, dict):
        return mapped
    for source, targets in matrix.items():
        if not isinstance(targets, dict):
            continue
        src_label = action_map.get(str(source), str(source))
        row: dict[str, float] = {}
        for target, prob in targets.items():
            dst_label = action_map.get(str(target), str(target))
            try:
                row[dst_label] = float(prob)
            except (TypeError, ValueError):
                continue
        if row:
            mapped[src_label] = row
    return mapped


def _map_forbidden_rules(rules: object, action_map: dict[str, str]) -> list[dict[str, object]]:
    """Map forbidden/constraint rules to action labels."""
    mapped: list[dict[str, object]] = []
    if not isinstance(rules, list):
        return mapped
    for item in rules:
        if not isinstance(item, dict):
            continue
        src = item.get("from")
        dst = item.get("to")
        if src is None or dst is None:
            continue
        mapped.append(
            {
                "from": action_map.get(str(src), str(src)),
                "to": action_map.get(str(dst), str(dst)),
                "rule": item.get("rule", "forbidden transition"),
                "score": item.get("score", 1.0),
            }
        )
    return mapped


def _normalize_papb_dataset(data: object, source_path: str | Path | None) -> dict[str, object]:
    action_map = _resolve_action_map(data, source_path)
    sequences = _extract_sequences_from_data(data)
    mapped_sequences = [_map_sequence_items(seq, action_map) for seq in sequences]
    normal_templates: list[list[str]] = []
    for seq in mapped_sequences:
        labels = _sequence_labels(seq)
        if labels:
            normal_templates.append(labels)
    if not isinstance(data, dict):
        data = {}

    return {
        "action_map": action_map,
        "normal_templates": normal_templates,
        "training_sequences": mapped_sequences,
        "max_repeats": _map_action_dict_keys(data.get("max_repeats", {}), action_map),
        "critical_actions": _map_action_list(data.get("critical_actions", []), action_map),
        "noncritical_actions": _map_action_list(data.get("noncritical_actions", []), action_map),
        "embedding_centers": data.get("embedding_centers", {}),
        "embedding_thresholds": data.get("embedding_thresholds", {}),
        "embedding_weight": data.get("embedding_weight", 0.35),
        "transition_matrix": _map_transition_matrix(data.get("transition_matrix", {}), action_map),
        "forbidden_transitions": _map_forbidden_rules(
            data.get("forbidden_transitions", data.get("state_constraint_rules", [])),
            action_map,
        ),
        "transition_risk_threshold": data.get("transition_risk_threshold", 0.15),
        "max_edit_distance": data.get("max_edit_distance", 1),
        "max_error_ratio": data.get("max_error_ratio", 0.0),
    }


def _map_evaluation_sequences(
    records: Iterable[object],
    action_map: dict[str, str],
) -> list[dict[str, object]]:
    mapped: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        sequence = record.get("actions", record.get("sequence", []))
        mapped_items = _map_sequence_items(sequence, action_map)
        mapped_record = dict(record)
        mapped_record["actions"] = _sequence_labels(mapped_items)
        mapped.append(mapped_record)
    return mapped


def _read_json(path: str | Path, default):
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: str | Path, data) -> None:
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _review_id(actions: list[str]) -> str:
    payload = "|".join(actions) + "|" + datetime.now(timezone.utc).isoformat()
    return "rv_" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def add_pending_review(
    review_path: str | Path,
    *,
    actions: list[str],
    result: dict[str, object],
) -> dict[str, object]:
    store = _read_json(review_path, {"pending": [], "reviewed": []})
    existing = {
        tuple(item.get("actions", []))
        for item in store.get("pending", [])
        if item.get("status") == "PENDING"
    }
    if tuple(actions) in existing:
        return {"added": False, "reason": "already pending"}

    item = {
        "review_id": _review_id(actions),
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "actions": actions,
        "papb_status": result.get("status"),
        "reason": result.get("violations", [{}])[0].get("reason", ""),
        "template_match": result.get("template_match", {}),
    }
    store.setdefault("pending", []).append(item)
    store.setdefault("reviewed", [])
    _write_json(review_path, store)
    return {"added": True, "item": item}


def review_sequence(
    review_path: str | Path,
    dataset_path: str | Path,
    review_id: str,
    decision: str,
    *,
    comment: str = "",
) -> dict[str, object]:
    store = _read_json(review_path, {"pending": [], "reviewed": []})
    pending = store.get("pending", [])
    item = next((entry for entry in pending if entry.get("review_id") == review_id), None)
    if item is None:
        raise ValueError(f"Review item not found: {review_id}")

    pending.remove(item)
    item["status"] = decision
    item["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    item["comment"] = comment
    store.setdefault("reviewed", []).append(item)
    _write_json(review_path, store)

    if decision == "ACCEPT_NORMAL":
        dataset = _read_json(dataset_path, {})
        dataset.setdefault("training_sequences", [])
        dataset["training_sequences"].append(item["actions"])
        _write_json(dataset_path, dataset)

    return item


def _parse_sequence(value: str) -> list[str]:
    return [
        part.strip()
        for part in value.replace("->", ",").split(",")
        if part.strip()
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate procedural action-label sequences with PAPB.")
    parser.add_argument("--dataset", required=True, help="JSON file with normal_templates and optional evaluation_sequences.")
    parser.add_argument("--sequence", default="", help="Action sequence, e.g. start,inspect_area,pick_tool or start->inspect_area.")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate dataset evaluation_sequences.")
    parser.add_argument("--train-out", default="", help="Fit a statistical PAPB model from normal training records and save it.")
    parser.add_argument("--review-out", default="", help="Write UNKNOWN_VALIDITY sequences to this pending-review JSON file.")
    parser.add_argument("--list-review", default="", help="List pending review items from this JSON file.")
    parser.add_argument("--approve", default="", help="Approve a review_id as normal and append it to dataset training_sequences.")
    parser.add_argument("--reject", default="", help="Reject a review_id as anomaly.")
    parser.add_argument("--comment", default="", help="Review comment for --approve/--reject.")
    parser.add_argument("--max-edit-distance", type=int, default=None, help="Allowed non-critical edit distance.")
    parser.add_argument("--max-error-ratio", type=float, default=None, help="Allowed non-critical edit ratio.")
    parser.add_argument("--critical-min-support", type=float, default=0.8, help="Mark actions appearing in this fraction of templates as critical during training.")
    parser.add_argument("--noncritical-actions", default="", help="Comma-separated actions that may be tolerated when missing/substituted.")
    parser.add_argument("--embedding-threshold-margin", type=float, default=3.0, help="Embedding threshold = mean distance + margin * std.")
    parser.add_argument("--min-embedding-threshold", type=float, default=0.15, help="Minimum learned embedding threshold.")
    parser.add_argument("--no-require-terminal", action="store_true", help="Allow prefixes that have not reached a terminal action.")
    args = parser.parse_args()

    if args.list_review:
        store = _read_json(args.list_review, {"pending": [], "reviewed": []})
        for item in store.get("pending", []):
            print(
                f"{item.get('review_id')}: status={item.get('status')} "
                f"actions={item.get('actions')}"
            )
        return

    if args.approve or args.reject:
        review_path = args.review_out or Path(args.dataset).with_name("papb_pending_review.json")
        decision = "ACCEPT_NORMAL" if args.approve else "REJECT_ANOMALY"
        review_id = args.approve or args.reject
        item = review_sequence(
            review_path,
            args.dataset,
            review_id,
            decision,
            comment=args.comment,
        )
        print(json.dumps(item, ensure_ascii=False, indent=2))
        return

    if args.train_out:
        validator = PapbValidator.fit_from_json(
            args.dataset,
            max_edit_distance=args.max_edit_distance if args.max_edit_distance is not None else 1,
            max_error_ratio=args.max_error_ratio if args.max_error_ratio is not None else 0.0,
            critical_min_support=args.critical_min_support,
            noncritical_actions=[part.strip() for part in args.noncritical_actions.split(",") if part.strip()],
            embedding_threshold_margin=args.embedding_threshold_margin,
            min_embedding_threshold=args.min_embedding_threshold,
            require_terminal=not args.no_require_terminal,
        )
        validator.save_model(args.train_out)
        print(f"saved_model={Path(args.train_out).resolve()}")
        if not args.evaluate and not args.sequence:
            return
    else:
        validator = PapbValidator.from_json(
            args.dataset,
            max_edit_distance=args.max_edit_distance,
            max_error_ratio=args.max_error_ratio,
            require_terminal=not args.no_require_terminal,
        )

    if args.evaluate:
        report = validator.evaluate_json(args.dataset)
        print(f"accuracy={report['accuracy']:.3f} ({report['correct']}/{report['total']})")
        for row in report["rows"]:
            marker = "OK" if row["correct"] else "FAIL"
            print(
                f"{marker} {row['id']}: expected={row['expected_status']} "
                f"predicted={row['predicted_status']}"
            )
        return

    if args.sequence:
        actions = _parse_sequence(args.sequence)
        result = validator.validate_sequence(actions)
        if args.review_out and result.get("status") == "UNKNOWN_VALIDITY":
            result["review"] = add_pending_review(
                args.review_out,
                actions=actions,
                result=result,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    parser.error("Provide --evaluate or --sequence.")


if __name__ == "__main__":
    main()
