#!/bin/bash
# ============================================================
# Packet-level Fine-tuning for ET-BERT
# 7-class classification: normal(0) + 6 anomaly types(1-6)
# Paper params: lr=2e-5, epochs=10, batch_size=48 (fp32)
# GPU memory: ~20-24 GB
# ============================================================

cd "$(dirname "$0")/.."

python fine-tuning/run_classifier.py \
    --pretrained_model_path models/pre-trained_model.bin \
    --output_model_path models/packet_classifier.bin \
    --vocab_path models/encryptd_vocab.txt \
    --config_path models/bert_base_config.json \
    --train_path datasets/packet/train_dataset.tsv \
    --dev_path datasets/packet/valid_dataset.tsv \
    --test_path datasets/packet/test_dataset.tsv \
    --embedding word_pos_seg \
    --encoder transformer \
    --mask fully_visible \
    --layernorm_positioning post \
    --pooling first \
    --tokenizer bert \
    --seq_length 512 \
    --batch_size 24 \
    --learning_rate 2e-5 \
    --dropout 0.5 \
    --epochs_num 10 \
    --optimizer adamw \
    --scheduler linear \
    --warmup 0.1 \
    --report_steps 500 \
    --seed 42
