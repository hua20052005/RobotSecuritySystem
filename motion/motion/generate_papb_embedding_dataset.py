from __future__ import annotations

import json
import random
from pathlib import Path


OUT = Path(__file__).with_name("papb_embedding_sequences.json")
RNG = random.Random(42)


NORMAL_TEMPLATES = [
    ["start", "inspect_area", "pick_tool", "grind_beans", "prepare_filter", "boil_water", "pour_water", "serve", "clean_tool", "shutdown"],
    ["start", "inspect_area", "pick_tool", "prepare_filter", "grind_beans", "boil_water", "pour_water", "stir", "serve", "clean_tool", "shutdown"],
    ["start", "pick_cup", "boil_water", "prepare_filter", "pour_water", "serve", "shutdown"],
    ["start", "inspect_area", "pick_part", "align_part", "tighten_screw", "quality_check", "pack_item", "shutdown"],
    ["start", "pick_part", "align_part", "quality_check", "tighten_screw", "quality_check", "pack_item", "shutdown"],
]


def center_for(template_idx: int, pos: int, action: str) -> list[float]:
    base = (sum(ord(ch) for ch in action) % 97) / 97
    return [
        round(base + template_idx * 0.20, 4),
        round((pos + 1) * 0.18, 4),
        round((len(action) % 11) * 0.11, 4),
        round(((template_idx + pos) % 7) * 0.13, 4),
    ]


def noisy(values: list[float], scale: float = 0.035) -> list[float]:
    return [round(value + RNG.uniform(-scale, scale), 4) for value in values]


def shifted(values: list[float], shift: float = 1.4) -> list[float]:
    return [round(value + shift + RNG.uniform(0.05, 0.16), 4) for value in values]


def key(template_idx: int, pos: int, action: str) -> str:
    return f"template:{template_idx}:pos:{pos}:action:{action}"


def build_centers() -> tuple[dict[str, list[float]], dict[str, float]]:
    centers: dict[str, list[float]] = {}
    thresholds: dict[str, float] = {}
    for template_idx, template in enumerate(NORMAL_TEMPLATES, start=1):
        for pos, action in enumerate(template):
            k = key(template_idx, pos, action)
            centers[k] = center_for(template_idx, pos, action)
            thresholds[k] = 0.22
    return centers, thresholds


def actions_from_template(
    template_index: int,
    *,
    omit_positions: set[int] | None = None,
    replace: dict[int, str] | None = None,
    extra_tail: list[str] | None = None,
    bad_embedding_positions: set[int] | None = None,
) -> list[dict[str, object]]:
    omit_positions = omit_positions or set()
    replace = replace or {}
    bad_embedding_positions = bad_embedding_positions or set()
    template = NORMAL_TEMPLATES[template_index - 1]
    rows: list[dict[str, object]] = []
    for pos, action in enumerate(template):
        if pos in omit_positions:
            continue
        label = replace.get(pos, action)
        center = center_for(template_index, pos, action)
        embedding = shifted(center) if pos in bad_embedding_positions else noisy(center)
        rows.append(
            {
                "label": label,
                "confidence": 0.9 if label == action else 0.58,
                "embedding": embedding,
            }
        )
    for label in extra_tail or []:
        rows.append(
            {
                "label": label,
                "confidence": 0.93,
                "embedding": shifted([0.1, 0.2, 0.3, 0.4]),
            }
        )
    return rows


def main() -> None:
    centers, thresholds = build_centers()
    data = {
        "description": "Synthetic PAPB dataset with action labels, confidences, and embeddings.",
        "normal_templates": NORMAL_TEMPLATES,
        "training_sequences": [
            {
                "id": f"train_template_{idx}",
                "actions": actions_from_template(idx),
            }
            for idx in range(1, len(NORMAL_TEMPLATES) + 1)
        ],
        "max_edit_distance": 1,
        "max_repeats": {
            "quality_check": 2,
            "stir": 2,
            "inspect_area": 1,
        },
        "critical_actions": [
            "boil_water",
            "align_part",
            "tighten_screw",
            "shutdown",
        ],
        "noncritical_actions": [
            "prepare_filter",
            "stir",
            "clean_tool",
        ],
        "embedding_centers": centers,
        "embedding_thresholds": thresholds,
        "evaluation_sequences": [
            {
                "id": "embed_normal_coffee",
                "expected_status": "NORMAL",
                "actions": actions_from_template(1),
            },
            {
                "id": "embed_normal_assembly",
                "expected_status": "NORMAL",
                "actions": actions_from_template(4),
            },
            {
                "id": "embed_tolerated_missing_filter",
                "expected_status": "NORMAL_WITH_TOLERANCE",
                "actions": actions_from_template(1, omit_positions={4}),
            },
            {
                "id": "embed_error_bad_boil_water_feature",
                "expected_status": "ANOMALY",
                "actions": actions_from_template(3, bad_embedding_positions={2}),
            },
            {
                "id": "embed_error_extra_after_shutdown",
                "expected_status": "ANOMALY",
                "actions": actions_from_template(3, extra_tail=["clean_tool"]),
            },
            {
                "id": "embed_error_missing_critical_align",
                "expected_status": "ANOMALY",
                "actions": actions_from_template(4, omit_positions={3}),
            },
        ],
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
