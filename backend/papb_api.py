from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.auth import optional_user
from backend.db import create_task

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAPB_ROOT = PROJECT_ROOT / "motion" / "motion"
DEFAULT_DATASET = PAPB_ROOT / "papb_competition_sequences.json"
DEFAULT_MODEL = PAPB_ROOT / "papb_trained_model.json"
DEFAULT_REVIEW = PAPB_ROOT / "papb_pending_review.json"

if str(PAPB_ROOT) not in sys.path:
    sys.path.insert(0, str(PAPB_ROOT))

from papb_validator import PapbValidator, add_pending_review, review_sequence  # noqa: E402

router = APIRouter(prefix="/api/papb", tags=["papb"])

ACTION_ALIASES = {
    "down": "stand",
    "up": "stand",
    "lie_down": "stand",
    "posture_toggle": "stand",
    "back": "move",
    "backward": "move",
    "forword": "move",
    "forward": "move",
    "left": "move",
    "right": "move",
    "walk": "move",
    "walk_slow": "move",
    "walk_mid": "move",
    "run_fast": "move",
    "step": "moonwalk",
    "twist_body": "twistBody",
    "twistbody": "twistBody",
    "side_jump": "twistJump",
    "twist_jump": "twistJump",
    "forward_jump": "jump",
    "dance": "dance1",
    "dance2": "dance1",
    "站立": "stand",
    "趴下": "stand",
    "蹲下": "stand",
    "移动": "move",
    "前进": "move",
    "后退": "move",
    "左移": "move",
    "右移": "move",
    "太空步": "moonwalk",
    "打招呼": "hello",
    "前跳": "jump",
    "扭身体": "twistBody",
    "扭身跳": "twistJump",
    "后空翻": "backflip",
    "跳舞": "dance1",
}


def _canonical_action_label(value: object) -> str:
    label = str(value).strip()
    if not label:
        return ""
    return ACTION_ALIASES.get(label, ACTION_ALIASES.get(label.lower(), label))


class ActionItem(BaseModel):
    label: str
    confidence: Optional[float] = None
    embedding: Optional[List[float]] = None


class DetectRequest(BaseModel):
    actions: Optional[List[Union[str, ActionItem]]] = None
    sequence: str = ""
    auto_review: bool = True
    require_terminal: bool = True
    save_history: bool = True
    source: str = "manual"
    scenario: str = "general"


class ReviewRequest(BaseModel):
    decision: str = Field(..., pattern="^(ACCEPT_NORMAL|REJECT_ANOMALY)$")
    comment: str = ""


class RetrainRequest(BaseModel):
    critical_min_support: float = 0.8
    noncritical_actions: List[str] = Field(default_factory=list)
    max_edit_distance: int = 1
    max_error_ratio: float = 0.0


class TrainingSequenceRequest(BaseModel):
    actions: List[str] = Field(default_factory=list)
    note: str = ""


class NextActionRequest(BaseModel):
    history: List[str] = Field(default_factory=list)
    sequence: str = ""
    actual_action: Optional[str] = None
    top_k: int = Field(default=5, ge=1, le=20)
    scenario: str = "general"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_sequence_text(value: str) -> List[str]:
    normalized = (
        value.replace("->", ",")
        .replace("→", ",")
        .replace("\r\n", ",")
        .replace("\n", ",")
        .replace("，", ",")
        .replace("、", ",")
    )
    return [part.strip() for part in normalized.split(",") if part.strip()]


def _model_dump(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_none=True)
    return model.dict(exclude_none=True)


def _normalize_actions(payload: DetectRequest) -> List[Union[str, Dict[str, Any]]]:
    if payload.actions:
        normalized: List[Union[str, Dict[str, Any]]] = []
        for item in payload.actions:
            if isinstance(item, str):
                label = _canonical_action_label(item)
                if label:
                    normalized.append(label)
            else:
                data = _model_dump(item)
                data["label"] = _canonical_action_label(data.get("label", ""))
                if data["label"]:
                    normalized.append(data)
        return normalized
    return [
        label
        for item in _parse_sequence_text(payload.sequence)
        if (label := _canonical_action_label(item))
    ]


def _labels(actions: List[Union[str, Dict[str, Any]]]) -> List[str]:
    labels: List[str] = []
    for item in actions:
        if isinstance(item, dict):
            label = str(item.get("label", "")).strip()
        else:
            label = str(item).strip()
        if label:
            labels.append(label)
    return labels


def _load_validator() -> PapbValidator:
    if DEFAULT_MODEL.exists():
        return PapbValidator.from_json(DEFAULT_MODEL)
    if DEFAULT_DATASET.exists():
        return PapbValidator.fit_from_json(DEFAULT_DATASET)
    raise HTTPException(status_code=500, detail=f"PAPB dataset not found: {DEFAULT_DATASET}")


def _pending_store() -> Dict[str, Any]:
    store = _read_json(DEFAULT_REVIEW, {"pending": [], "reviewed": []})
    store.setdefault("pending", [])
    store.setdefault("reviewed", [])
    return store


def _dataset() -> Dict[str, Any]:
    return _read_json(DEFAULT_DATASET, {})


def _model_data() -> Dict[str, Any]:
    return _read_json(DEFAULT_MODEL, {})


def _templates() -> List[List[str]]:
    dataset = _dataset()
    model = _model_data()
    return model.get("normal_templates") or dataset.get("normal_templates") or []


def _summary() -> Dict[str, Any]:
    dataset = _dataset()
    model = _model_data()
    review = _pending_store()
    templates = _templates()
    training_sequences = dataset.get("training_sequences") or dataset.get("normal_sequences") or []
    expert_sequences = dataset.get("expert_sequences") or []
    actions = sorted({action for template in templates for action in template})
    return {
        "dataset_path": str(DEFAULT_DATASET),
        "model_path": str(DEFAULT_MODEL),
        "review_path": str(DEFAULT_REVIEW),
        "model_exists": DEFAULT_MODEL.exists(),
        "template_count": len(templates),
        "training_sequence_count": len(training_sequences),
        "expert_sequence_count": len(expert_sequences),
        "action_count": len(actions),
        "actions": actions,
        "critical_actions": model.get("critical_actions", dataset.get("critical_actions", [])),
        "noncritical_actions": model.get("noncritical_actions", dataset.get("noncritical_actions", [])),
        "transition_source_count": len(model.get("transition_matrix", {})),
        "context_count": len(model.get("context_transitions", {})),
        "embedding_count": len(model.get("embedding_centers", {})),
        "forbidden_rule_count": len(model.get("forbidden_transitions", [])),
        "pending_count": len([item for item in review["pending"] if item.get("status") == "PENDING"]),
        "reviewed_count": len(review["reviewed"]),
    }


def _task_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    status = str(result.get("status", "UNKNOWN"))
    return {
        "status": status,
        "action_count": result.get("action_count", 0),
        "transition_count": result.get("transition_count", 0),
        "violation_count": len(result.get("violations", [])),
        "unknown": status == "UNKNOWN_VALIDITY",
        "abnormal": 1 if status == "ANOMALY" else 0,
    }


@router.get("/summary")
def papb_summary() -> Dict[str, Any]:
    return _summary()


@router.get("/model")
def model_detail() -> Dict[str, Any]:
    dataset = _dataset()
    model = _model_data()
    return {
        "summary": _summary(),
        "normal_templates": _templates(),
        "training_sequences": dataset.get("training_sequences", []),
        "evaluation_sequences": dataset.get("evaluation_sequences", []),
        "expert_sequences": dataset.get("expert_sequences", []),
        "max_repeats": model.get("max_repeats", dataset.get("max_repeats", {})),
        "critical_actions": model.get("critical_actions", dataset.get("critical_actions", [])),
        "noncritical_actions": model.get("noncritical_actions", dataset.get("noncritical_actions", [])),
        "transition_matrix": model.get("transition_matrix", {}),
        "context_transitions": model.get("context_transitions", {}),
        "context_support": model.get("context_support", {}),
        "embedding_centers": model.get("embedding_centers", {}),
        "embedding_kind": model.get("embedding_kind", "external"),
        "forbidden_transitions": model.get("forbidden_transitions", []),
        "scenario_rules": model.get("scenario_rules", {}),
        "transition_risk_threshold": model.get("transition_risk_threshold", 0.15),
    }


@router.post("/training-sequences")
def add_training_sequence(payload: TrainingSequenceRequest) -> Dict[str, Any]:
    actions = [
        label
        for action in payload.actions
        if (label := _canonical_action_label(action))
    ]
    if not actions:
        raise HTTPException(status_code=400, detail="请至少提供一个动作标签")

    dataset = _dataset()
    dataset.setdefault("training_sequences", [])
    dataset["training_sequences"].append(actions)
    dataset.setdefault("normal_templates", [])
    if actions not in dataset["normal_templates"]:
        dataset["normal_templates"].append(actions)
    _write_json(DEFAULT_DATASET, dataset)
    return {"added": actions, "summary": _summary()}


@router.post("/detect")
def detect_sequence(
    payload: DetectRequest,
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    actions = _normalize_actions(payload)
    labels = _labels(actions)
    if not labels:
        raise HTTPException(status_code=400, detail="请至少输入一个动作标签")

    validator = _load_validator()
    result = validator.validate_sequence(
        actions,
        require_terminal=payload.require_terminal,
        scenario=payload.scenario,
    )
    result["input_actions"] = labels
    result["source"] = payload.source
    result["scenario"] = payload.scenario

    if payload.auto_review and result.get("status") == "UNKNOWN_VALIDITY":
        result["review"] = add_pending_review(
            DEFAULT_REVIEW,
            actions=labels,
            result=result,
        )

    if payload.save_history:
        task_id = "papb_" + uuid.uuid4().hex[:10]
        result["task_id"] = task_id
        create_task(
            task_id=task_id,
            module="papb",
            title=f"PAPB流程检测 - {result.get('status')}",
            parameters={
                "actions": labels,
                "auto_review": payload.auto_review,
                "require_terminal": payload.require_terminal,
                "source": payload.source,
                "scenario": payload.scenario,
            },
            summary=_task_summary(result),
            result=result,
            files={"dataset": str(DEFAULT_DATASET), "model": str(DEFAULT_MODEL)},
            user_id=int(user["id"]) if isinstance(user, dict) else None,
        )
    return result


@router.post("/predict-next")
def predict_next_action(payload: NextActionRequest) -> Dict[str, Any]:
    history = payload.history or _parse_sequence_text(payload.sequence)
    history = [
        label
        for action in history
        if (label := _canonical_action_label(action))
    ]
    actual = (
        _canonical_action_label(payload.actual_action)
        if payload.actual_action
        else None
    )
    validator = _load_validator()
    return validator.predict_next_actions(
        history,
        actual_action=actual,
        top_k=payload.top_k,
        scenario=payload.scenario,
    )


@router.get("/review/pending")
def pending_review() -> Dict[str, Any]:
    store = _pending_store()
    pending = [item for item in store["pending"] if item.get("status") == "PENDING"]
    return {"pending": pending, "reviewed": store["reviewed"]}


@router.post("/review/{review_id}")
def submit_review(review_id: str, payload: ReviewRequest) -> Dict[str, Any]:
    try:
        item = review_sequence(
            DEFAULT_REVIEW,
            DEFAULT_DATASET,
            review_id,
            payload.decision,
            comment=payload.comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"item": item, "summary": _summary()}


@router.post("/retrain")
def retrain_model(payload: RetrainRequest) -> Dict[str, Any]:
    if not DEFAULT_DATASET.exists():
        raise HTTPException(status_code=500, detail=f"PAPB dataset not found: {DEFAULT_DATASET}")

    validator = PapbValidator.fit_from_json(
        DEFAULT_DATASET,
        critical_min_support=payload.critical_min_support,
        noncritical_actions=payload.noncritical_actions,
        max_edit_distance=payload.max_edit_distance,
        max_error_ratio=payload.max_error_ratio,
        require_terminal=True,
    )
    validator.save_model(DEFAULT_MODEL)
    evaluation = {}
    dataset = _dataset()
    if dataset.get("evaluation_sequences"):
        evaluation = validator.evaluate_dataset(dataset["evaluation_sequences"])
    return {
        "message": "PAPB model retrained",
        "summary": _summary(),
        "evaluation": evaluation,
    }
