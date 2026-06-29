#!/bin/bash
# V3 消融实验: 8 位置采样 (8×60B=480 bigrams)
cd "$(dirname "$0")/.."
python fine-tuning/run_classifier.py \
    --pretrained_model_path models/pre-trained_model.bin \
    --output_model_path models/flow_v3_8pos.bin \
    --vocab_path models/encryptd_vocab.txt \
    --config_path models/bert_base_config.json \
    --train_path datasets/flow_v3_8pos/train_dataset.tsv \
    --dev_path datasets/flow_v3_8pos/valid_dataset.tsv \
    --test_path datasets/flow_v3_8pos/test_dataset.tsv \
    --pooling first --tokenizer bert --seq_length 512 \
    --batch_size 32 --learning_rate 3e-5 --dropout 0.5 \
    --epochs_num 10 --report_steps 100 --seed 42
