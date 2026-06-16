from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np
import pickle

from .features import extract_features
from .pcap_signal import LengthMode, Protocol, iter_pcaps, pcap_to_signal
from .templates import ActionTemplate, build_templates


ClassifierName = Literal["rf", "xgboost"]


@dataclass
class ActionModel:
    classifier: object
    labels: list[str]
    templates: dict[str, ActionTemplate]
    feature_names: list[str]
    bin_size: float
    protocol: Protocol
    length_mode: LengthMode
    trim: bool


@dataclass(frozen=True)
class DatasetItem:
    label: str
    path: Path
    signal: np.ndarray


class LabelEncodedClassifier:
    """Small adapter for classifiers that require integer labels."""

    def __init__(self, estimator: object):
        try:
            from sklearn.preprocessing import LabelEncoder
        except ImportError as exc:
            raise RuntimeError("scikit-learn is required. Run: pip install -e .") from exc

        self.estimator = estimator
        self.encoder = LabelEncoder()
        self.classes_: np.ndarray | None = None

    def fit(self, x: np.ndarray, y: np.ndarray) -> "LabelEncodedClassifier":
        encoded = self.encoder.fit_transform(y)
        self.estimator.fit(x, encoded)
        self.classes_ = self.encoder.classes_
        return self

    def predict(self, x: np.ndarray) -> np.ndarray:
        encoded = self.estimator.predict(x)
        return self.encoder.inverse_transform(np.asarray(encoded, dtype=int))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return self.estimator.predict_proba(x)


def load_dataset(
    data_dir: str | Path,
    *,
    bin_size: float,
    protocol: Protocol,
    positive_ip: str | None,
    length_mode: LengthMode,
) -> list[DatasetItem]:
    items: list[DatasetItem] = []
    pcaps = list(iter_pcaps(data_dir))
    if not pcaps:
        raise ValueError(f"No pcap files found under {data_dir}")

    total = len(pcaps)
    for idx, (label, path) in enumerate(pcaps, start=1):
        print(f"[signal] Loading {idx}/{total}: {path}", flush=True)
        ts = pcap_to_signal(
            path,
            bin_size=bin_size,
            protocol=protocol,
            positive_ip=positive_ip,
            length_mode=length_mode,
        )
        items.append(DatasetItem(label=label, path=path, signal=ts.signal))
    return items


def train_action_model(
    items: list[DatasetItem],
    *,
    bin_size: float,
    protocol: Protocol,
    length_mode: LengthMode,
    classifier_name: ClassifierName = "rf",
    trim: bool = True,
) -> ActionModel:
    labeled_signals = [(item.label, item.signal) for item in items]
    templates = build_templates(labeled_signals, trim=trim)
    labels = sorted({item.label for item in items})
    if len(labels) < 2:
        raise ValueError("Need at least two action labels to train a classifier")

    x, y, feature_names = build_feature_matrix(
        items,
        templates=templates,
        bin_size=bin_size,
        trim=trim,
    )
    classifier = _make_classifier(classifier_name, sample_count=len(items))
    classifier.fit(x, y)

    return ActionModel(
        classifier=classifier,
        labels=labels,
        templates=templates,
        feature_names=feature_names,
        bin_size=bin_size,
        protocol=protocol,
        length_mode=length_mode,
        trim=trim,
    )


def build_feature_matrix(
    items: list[DatasetItem],
    *,
    templates: dict[str, ActionTemplate],
    bin_size: float,
    trim: bool,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    rows: list[np.ndarray] = []
    labels: list[str] = []
    feature_names: list[str] | None = None

    for item in items:
        fv = extract_features(item.signal, templates, bin_size=bin_size, trim=trim)
        if feature_names is None:
            feature_names = fv.names
        elif feature_names != fv.names:
            raise RuntimeError("Feature names changed between samples")
        rows.append(fv.values)
        labels.append(item.label)

    return np.vstack(rows), np.asarray(labels), feature_names or []


def leave_one_out_report(
    items: list[DatasetItem],
    *,
    bin_size: float,
    protocol: Protocol,
    length_mode: LengthMode,
    classifier_name: ClassifierName,
    trim: bool,
) -> dict[str, object]:
    try:
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    except ImportError as exc:
        raise RuntimeError("scikit-learn is required. Run: pip install -e .") from exc

    labels = sorted({item.label for item in items})
    y_true: list[str] = []
    y_pred: list[str] = []

    for idx, test_item in enumerate(items):
        train_items = [item for j, item in enumerate(items) if j != idx]
        train_labels = {item.label for item in train_items}
        if test_item.label not in train_labels:
            continue

        templates = build_templates(
            [(item.label, item.signal) for item in train_items],
            trim=trim,
        )
        x_train, y_train, _ = build_feature_matrix(
            train_items,
            templates=templates,
            bin_size=bin_size,
            trim=trim,
        )
        fv = extract_features(test_item.signal, templates, bin_size=bin_size, trim=trim)
        clf = _make_classifier(classifier_name, sample_count=len(train_items))
        clf.fit(x_train, y_train)
        pred = str(clf.predict(fv.values.reshape(1, -1))[0])
        y_true.append(test_item.label)
        y_pred.append(pred)

    if not y_true:
        return {
            "accuracy": None,
            "labels": labels,
            "confusion_matrix": None,
            "classification_report": "Not enough samples per class for leave-one-out.",
        }

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=labels,
            zero_division=0,
        ),
    }


def predict_pcap(
    model: ActionModel,
    pcap_path: str | Path,
    *,
    positive_ip: str | None = None,
) -> dict[str, object]:
    ts = pcap_to_signal(
        pcap_path,
        bin_size=model.bin_size,
        protocol=model.protocol,
        positive_ip=positive_ip,
        length_mode=model.length_mode,
    )
    fv = extract_features(
        ts.signal,
        model.templates,
        bin_size=model.bin_size,
        trim=model.trim,
    )
    pred = str(model.classifier.predict(fv.values.reshape(1, -1))[0])
    result: dict[str, object] = {"predicted": pred}

    if hasattr(model.classifier, "predict_proba"):
        probs = model.classifier.predict_proba(fv.values.reshape(1, -1))[0]
        classes = [str(cls) for cls in model.classifier.classes_]
        proba = {label: float(prob) for label, prob in zip(classes, probs)}
        result["proba"] = dict(sorted(proba.items()))
        result["confidence"] = float(max(proba.values())) if proba else None
    return result


def save_model(model: ActionModel, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        pickle.dump(model, f)


def load_model(path: str | Path) -> ActionModel:
    with Path(path).open("rb") as f:
        return pickle.load(f)


def _make_classifier(classifier_name: ClassifierName, *, sample_count: int):
    if classifier_name == "rf":
        try:
            from sklearn.ensemble import RandomForestClassifier
        except ImportError as exc:
            raise RuntimeError("scikit-learn is required. Run: pip install -e .") from exc

        return RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
        )

    if classifier_name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise RuntimeError(
                "xgboost is not installed. Run: pip install -e .[xgboost]"
            ) from exc

        estimator = XGBClassifier(
            n_estimators=max(30, min(200, sample_count * 20)),
            max_depth=3,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=42,
        )
        return LabelEncodedClassifier(estimator)

    raise ValueError(f"Unsupported classifier: {classifier_name}")
