#!/bin/bash
# V3 消融实验: 全包采样 (64×7B=448 bigrams)
cd "$(dirname "$0")/.."
python fine-tuning/run_classifier.py \
    --pretrained_model_path models/pre-trained_model.bin \
    --output_model_path models/flow_v3_full.bin \
    --vocab_path models/encryptd_vocab.txt \
    --config_path models/bert_base_config.json \
    --train_path datasets/flow_v3_full/train_dataset.tsv \
    --dev_path datasets/flow_v3_full/valid_dataset.tsv \
    --test_path datasets/flow_v3_full/test_dataset.tsv \
    --pooling first --tokenizer bert --seq_length 512 \
    --batch_size 32 --learning_rate 3e-5 --dropout 0.5 \
    --epochs_num 10 --report_steps 100 --seed 42
