from __future__ import annotations

import argparse
from pathlib import Path

from .model import (
    leave_one_out_report,
    load_dataset,
    load_model,
    predict_pcap,
    save_model,
    train_action_model,
)
from .motion import (
    compare_models,
    load_motion_model,
    predict_action_sequence,
    predict_motion_pcap,
    save_motion_model,
    train_motion_model,
    write_training_outputs,
)
from .pcap_signal import pcap_to_signal, signal_summary

import json


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="robot-action",
        description="Recognize robot actions from PCAP traffic fingerprints.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_parser = sub.add_parser("inspect", help="Show signal summary for a pcap")
    inspect_parser.add_argument("--pcap", required=True)
    add_signal_args(inspect_parser)

    train_parser = sub.add_parser("train", help="Train an action classifier")
    train_parser.add_argument("--data-dir", required=True)
    train_parser.add_argument("--model-out", default="models/action_model.joblib")
    train_parser.add_argument("--classifier", choices=["rf", "xgboost"], default="rf")
    train_parser.add_argument(
        "--no-loo",
        action="store_true",
        help="Skip leave-one-out evaluation",
    )
    add_signal_args(train_parser)

    predict_parser = sub.add_parser("predict", help="Predict one pcap action")
    predict_parser.add_argument("--model", required=True)
    predict_parser.add_argument("--pcap", required=True)
    predict_parser.add_argument("--positive-ip", default=None)

    motion_train_parser = sub.add_parser(
        "train-motion",
        help="Train the motion sequence model and optionally the original signal model.",
    )
    motion_train_parser.add_argument("--data-dir", required=True)
    motion_train_parser.add_argument("--out-dir", default="outputs_motion_model")
    motion_train_parser.add_argument("--window-ms", type=int, default=100)
    motion_train_parser.add_argument("--clusters", type=int, default=8)
    motion_train_parser.add_argument("--include-ports", default="")
    motion_train_parser.add_argument("--exclude-ports", default="22")
    motion_train_parser.add_argument(
        "--clean-mode",
        choices=["none", "protocol"],
        default="none",
        help="protocol keeps only auto-discovered valid Unitree UDP control payloads.",
    )
    motion_train_parser.add_argument("--max-templates-per-action", type=int, default=2)
    motion_train_parser.add_argument("--threshold-padding", type=float, default=0.12)
    motion_train_parser.add_argument("--no-signal", action="store_true")
    motion_train_parser.add_argument("--no-amnar", action="store_true")
    motion_train_parser.add_argument("--signal-classifier", choices=["rf", "xgboost"], default="rf")
    motion_train_parser.add_argument("--signal-bin-size", type=float, default=0.02)
    motion_train_parser.add_argument("--signal-protocol", choices=["all", "tcp", "udp"], default="all")
    motion_train_parser.add_argument(
        "--signal-length-mode",
        choices=["packet", "ip", "transport", "payload"],
        default="packet",
    )
    motion_train_parser.add_argument("--signal-positive-ip", default=None)

    motion_predict_parser = sub.add_parser(
        "predict-motion",
        help="Predict one pcap or a directory with the trained motion model.",
    )
    motion_predict_parser.add_argument("--model", default="outputs_motion_model/motion_model.pkl")
    motion_predict_parser.add_argument("--pcap", required=True)
    motion_predict_parser.add_argument("--output", default="")
    motion_predict_parser.add_argument(
        "--signal-fusion",
        choices=["compare", "disagree", "signal_primary"],
        default="compare",
    )
    motion_predict_parser.add_argument("--signal-confidence", type=float, default=0.60)

    compare_parser = sub.add_parser(
        "compare",
        help="Evaluate motion and signal branches side by side on a labelled test directory.",
    )
    compare_parser.add_argument("--model", default="outputs_motion_model/motion_model.pkl")
    compare_parser.add_argument("--test-dir", required=True)
    compare_parser.add_argument("--output", default="outputs_motion_model/comparison.json")
    compare_parser.add_argument(
        "--signal-fusion",
        choices=["compare", "disagree", "signal_primary"],
        default="compare",
    )

    sequence_parser = sub.add_parser(
        "predict-sequence",
        help="Recognize a sequence of actions inside one longer pcap.",
    )
    sequence_parser.add_argument("--model", default="outputs_motion_model/motion_model.pkl")
    sequence_parser.add_argument("--pcap", required=True)
    sequence_parser.add_argument("--output", default="sequence_results.json")
    sequence_parser.add_argument(
        "--method",
        choices=["dp", "activity", "scripted", "scan"],
        default="dp",
        help=(
            "dp guesses action order, scan classifies sliding windows, activity "
            "uses low-traffic gaps, scripted uses a known action transcript and "
            "optimizes boundaries."
        ),
    )
    sequence_parser.add_argument(
        "--transcript",
        default="",
        help="Comma-separated action script, e.g. stand,step,hello,stand.",
    )
    sequence_parser.add_argument(
        "--script-file",
        default="sequence_scripts.json",
        help="JSON mapping pcap stem to transcript for --method scripted.",
    )
    sequence_parser.add_argument("--min-segment-s", type=float, default=0.25)
    sequence_parser.add_argument("--max-segment-s", type=float, default=None)
    sequence_parser.add_argument("--step-s", type=float, default=0.5)
    sequence_parser.add_argument("--segment-penalty", type=float, default=0.02)

    eval_sequence_parser = sub.add_parser(
        "evaluate-sequences",
        help="Compare predicted sequence JSON files with a ground-truth JSON file.",
    )
    eval_sequence_parser.add_argument("--truth", default="sequence_ground_truth.json")
    eval_sequence_parser.add_argument("--pred-dir", default="outputs_motion_model/sequence_free_now")
    eval_sequence_parser.add_argument("--output", default="outputs_motion_model/sequence_eval.json")

    args = parser.parse_args()

    if args.command == "inspect":
        ts = pcap_to_signal(
            args.pcap,
            bin_size=args.bin_size,
            protocol=args.protocol,
            positive_ip=args.positive_ip,
            length_mode=args.length_mode,
        )
        for key, value in signal_summary(ts).items():
            print(f"{key}: {value}")
        return

    if args.command == "evaluate-sequences":
        report = _evaluate_sequences(args.truth, args.pred_dir)
        _write_json(args.output, report)
        print(f"samples={report['samples']}")
        print(f"exact_accuracy={report['exact_accuracy']}")
        print(f"mean_edit_similarity={report['mean_edit_similarity']}")
        print(f"saved_evaluation={Path(args.output)}")
        for row in report["rows"]:
            print(
                f"{row['id']}: exact={row['exact']} "
                f"similarity={row['edit_similarity']:.3f} "
                f"truth={' -> '.join(row['truth'])} "
                f"pred={' -> '.join(row['predicted'])}"
            )
        return

    if args.command == "train":
        items = load_dataset(
            args.data_dir,
            bin_size=args.bin_size,
            protocol=args.protocol,
            positive_ip=args.positive_ip,
            length_mode=args.length_mode,
        )
        print(f"loaded_samples={len(items)}")
        labels = sorted({item.label for item in items})
        print(f"labels={', '.join(labels)}")

        if not args.no_loo:
            report = leave_one_out_report(
                items,
                bin_size=args.bin_size,
                protocol=args.protocol,
                length_mode=args.length_mode,
                classifier_name=args.classifier,
                trim=True,
            )
            print(f"leave_one_out_accuracy={report['accuracy']}")
            print("confusion_matrix_labels=" + ", ".join(report["labels"]))
            print(f"confusion_matrix={report['confusion_matrix']}")
            print(report["classification_report"])

        model = train_action_model(
            items,
            bin_size=args.bin_size,
            protocol=args.protocol,
            length_mode=args.length_mode,
            classifier_name=args.classifier,
            trim=True,
        )
        save_model(model, args.model_out)
        print(f"saved_model={Path(args.model_out)}")
        print(f"feature_count={len(model.feature_names)}")
        for label, template in model.templates.items():
            print(
                f"template {label}: samples={template.sample_count}, "
                f"length={template.length}"
            )
        return

    if args.command == "predict":
        model = load_model(args.model)
        result = predict_pcap(model, args.pcap, positive_ip=args.positive_ip)
        print(f"predicted={result['predicted']}")
        if "confidence" in result:
            print(f"confidence={result['confidence']:.4f}")
        if "proba" in result:
            print("proba:")
            for label, prob in result["proba"].items():
                print(f"  {label}: {prob:.4f}")
        return

    if args.command == "train-motion":
        include_ports = _parse_ports(args.include_ports) or None
        exclude_ports = _parse_ports(args.exclude_ports)
        model, report = train_motion_model(
            args.data_dir,
            window_ms=args.window_ms,
            clusters=args.clusters,
            include_ports=include_ports,
            exclude_ports=exclude_ports,
            clean_mode=args.clean_mode,
            max_templates_per_action=args.max_templates_per_action,
            threshold_padding=args.threshold_padding,
            train_signal=not args.no_signal,
            train_amnar=not args.no_amnar,
            signal_bin_size=args.signal_bin_size,
            signal_protocol=args.signal_protocol,
            signal_positive_ip=args.signal_positive_ip,
            signal_length_mode=args.signal_length_mode,
            signal_classifier=args.signal_classifier,
        )
        write_training_outputs(model, report, args.out_dir)
        print(f"saved_motion_model={Path(args.out_dir) / 'motion_model.pkl'}")
        print(f"motion_training_accuracy={report['motion_training_accuracy']}")
        print(f"labels={', '.join(report['labels'])}")
        print(f"windows={report['windows']}")
        if report.get("signal_report"):
            print(f"saved_signal_model={Path(args.out_dir) / 'signal_action_model.joblib'}")
        if report.get("amnar_report"):
            print("saved_amnar_payload_model=inside motion_model.pkl")
        return

    if args.command == "predict-motion":
        model = load_motion_model(args.model)
        path = Path(args.pcap)
        if path.is_dir():
            results = [
                predict_motion_pcap(
                    model,
                    pcap,
                    signal_fusion=args.signal_fusion,
                    signal_confidence=args.signal_confidence,
                )
                for pcap in sorted(path.rglob("*.pcap"))
            ]
        else:
            results = [
                predict_motion_pcap(
                    model,
                    path,
                    signal_fusion=args.signal_fusion,
                    signal_confidence=args.signal_confidence,
                )
            ]
        if args.output:
            _write_json(args.output, results)
            print(f"saved_results={Path(args.output)}")
        for result in results:
            print(
                f"{Path(result['pcap_file']).name}: "
                f"label={result.get('label')} status={result.get('status')} "
                f"motion={result.get('motion', {}).get('label')} "
                f"amnar={(result.get('amnar') or {}).get('predicted')} "
                f"signal={(result.get('signal') or {}).get('predicted')}"
            )
        return

    if args.command == "compare":
        model = load_motion_model(args.model)
        report = compare_models(model, args.test_dir, signal_fusion=args.signal_fusion)
        _write_json(args.output, report)
        print(f"samples={report['samples']}")
        print(f"motion_accuracy={report['motion_accuracy']}")
        print(f"amnar_accuracy={report['amnar_accuracy']}")
        print(f"signal_accuracy={report['signal_accuracy']}")
        print(f"final_accuracy={report['final_accuracy']}")
        print(f"saved_comparison={Path(args.output)}")
        return

    if args.command == "predict-sequence":
        model = load_motion_model(args.model)
        transcript = _parse_transcript(args.transcript)
        if args.method == "scripted" and transcript is None:
            transcript = _load_script_transcript(args.script_file, args.pcap)
        result = predict_action_sequence(
            model,
            args.pcap,
            method=args.method,
            transcript=transcript,
            min_segment_s=args.min_segment_s,
            max_segment_s=args.max_segment_s,
            step_s=args.step_s,
            segment_penalty=args.segment_penalty,
        )
        _write_json(args.output, result)
        print(f"saved_sequence_results={Path(args.output)}")
        actions = result.get("actions", [])
        if not actions:
            print(f"status={result.get('status')}")
            if result.get("status") == "NO_TRANSCRIPT":
                print(
                    "No transcript was found. Add this pcap stem to the script file "
                    "or pass --transcript manually."
                )
            return
        for idx, item in enumerate(actions, 1):
            t_start = item.get("t_start_s")
            t_end = item.get("t_end_s")
            time_range = (
                f"{t_start:.2f}s-{t_end:.2f}s"
                if isinstance(t_start, (int, float)) and isinstance(t_end, (int, float))
                else "unknown-time"
            )
            score = None
            if item.get("similarity") is not None:
                score = f"similarity={item['similarity']:.3f}"
            elif item.get("confidence") is not None:
                score = f"confidence={item['confidence']:.3f}"
            else:
                score = "score=unknown"
            print(
                f"{idx}: {item.get('label')} {item.get('status')} "
                f"{time_range} {score}"
            )
        return


def add_signal_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bin-size", type=float, default=0.02)
    parser.add_argument("--protocol", choices=["all", "tcp", "udp"], default="all")
    parser.add_argument("--positive-ip", default=None)
    parser.add_argument(
        "--length-mode",
        choices=["packet", "ip", "transport", "payload"],
        default="packet",
    )


def _parse_ports(value: str) -> set[int]:
    return {int(part.strip()) for part in value.split(",") if part.strip()}


def _parse_transcript(value: str) -> list[str] | None:
    if not value.strip():
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


def _load_script_transcript(script_file: str | Path, pcap_path: str | Path) -> list[str] | None:
    path = Path(script_file)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        scripts = json.load(f)
    value = scripts.get(Path(pcap_path).stem)
    if not value:
        return None
    return [str(item) for item in value]


def _evaluate_sequences(truth_path: str | Path, pred_dir: str | Path) -> dict[str, object]:
    truth_file = Path(truth_path)
    with truth_file.open("r", encoding="utf-8") as f:
        truth_data = json.load(f)
    pred_root = Path(pred_dir)
    rows = []
    for seq_id, item in sorted(truth_data.items()):
        truth = [str(label) for label in item.get("labels", [])]
        pred_file = pred_root / f"{seq_id}.json"
        if not pred_file.exists():
            predicted = []
            status = "MISSING_PREDICTION"
        else:
            with pred_file.open("r", encoding="utf-8") as f:
                pred_data = json.load(f)
            predicted = [str(action.get("label")) for action in pred_data.get("actions", [])]
            status = str(pred_data.get("status", "UNKNOWN"))
        distance = _label_edit_distance(truth, predicted)
        denom = max(len(truth), len(predicted), 1)
        similarity = 1.0 - distance / denom
        rows.append(
            {
                "id": seq_id,
                "status": status,
                "truth_zh": item.get("zh", []),
                "truth": truth,
                "predicted": predicted,
                "edit_distance": distance,
                "edit_similarity": similarity,
                "exact": truth == predicted,
            }
        )
    return {
        "samples": len(rows),
        "exact_accuracy": sum(1 for row in rows if row["exact"]) / max(len(rows), 1),
        "mean_edit_similarity": sum(float(row["edit_similarity"]) for row in rows) / max(len(rows), 1),
        "rows": rows,
    }


def _label_edit_distance(left: list[str], right: list[str]) -> int:
    prev = list(range(len(right) + 1))
    for i, left_item in enumerate(left, 1):
        cur = [i]
        for j, right_item in enumerate(right, 1):
            cur.append(
                min(
                    prev[j] + 1,
                    cur[j - 1] + 1,
                    prev[j - 1] + (left_item != right_item),
                )
            )
        prev = cur
    return prev[-1]


def _write_json(path: str | Path, data: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
