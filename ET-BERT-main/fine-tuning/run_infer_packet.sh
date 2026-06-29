#!/bin/bash
# ============================================================
# Packet-level Inference — evaluate on test set
# ============================================================

cd "$(dirname "$0")/.."

python inference/run_classifier_infer.py \
    --load_model_path models/packet_classifier.bin \
    --vocab_path models/encryptd_vocab.txt \
    --config_path models/bert_base_config.json \
    --test_path datasets/packet/test_dataset.tsv \
    --prediction_path datasets/packet/test_prediction.txt \
    --labels_num 7 \
    --embedding word_pos_seg \
    --encoder transformer \
    --mask fully_visible \
    --layernorm_positioning post \
    --pooling first \
    --tokenizer bert \
    --seq_length 512 \
    --batch_size 64 \
    --output_logits \
    --output_prob
