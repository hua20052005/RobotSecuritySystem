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
from .pcap_signal import pcap_to_signal, signal_summary


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


def add_signal_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bin-size", type=float, default=0.02)
    parser.add_argument("--protocol", choices=["all", "tcp", "udp"], default="all")
    parser.add_argument("--positive-ip", default=None)
    parser.add_argument(
        "--length-mode",
        choices=["packet", "ip", "transport", "payload"],
        default="packet",
    )


if __name__ == "__main__":
    main()
