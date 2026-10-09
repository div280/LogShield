"""
train_lstm.py -- Runner script to train and evaluate the LogShield LSTM
Autoencoder model on Windows Event Log shuffle attacks.

Usage:
    python scripts/train_lstm.py
"""
import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse
from src.models.lstm_model import train, evaluate, load_lstm

DATA_DIR = os.environ.get(
    'LOGSHIELD_DATA_DIR',
    r'C:\Users\shrey\OneDrive\Desktop\fdb_logshied'
)
DEFAULT_DATASET_PATH = os.path.join(DATA_DIR, 'logshield_shuffle_attacks.csv')


def main(dataset_path: str = DEFAULT_DATASET_PATH):
    """Execute training and testing pipeline."""
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at: {dataset_path}")
        sys.exit(1)

    t_start = time.time()
    print("Starting LogShield LSTM Sequence Autoencoder training pipeline...\n")

    # 1. Train Model
    train_results = train(
        csv_path=dataset_path,
        model_save_path='models_saved/lstm_ae.keras',
        meta_save_path='models_saved/lstm_meta.pkl',
        max_epochs=15,
        batch_size=256
    )

    model = train_results['model']
    meta = train_results['meta']
    test_df = train_results['test_df']

    # 2. Evaluate on TEST split
    eval_results = evaluate(
        test_df=test_df,
        model=model,
        meta=meta
    )

    # 3. Verify independent model reload
    print("\nVerifying model re-loading in clean sub-call...")
    loaded_model, loaded_meta = load_lstm('models_saved/lstm_ae.keras', 'models_saved/lstm_meta.pkl')
    assert loaded_model is not None, "Loaded model is None"
    assert 'threshold' in loaded_meta, "Loaded meta missing threshold"
    print("Model reload verification: PASSED.")

    total_time = time.time() - t_start
    print(f"\nTotal pipeline execution time: {total_time:.2f}s ({total_time/60:.2f} mins)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train and evaluate LogShield LSTM model.")
    parser.add_argument('csv_path', nargs='?', default=DEFAULT_DATASET_PATH, help="Path to input CSV dataset.")
    args = parser.parse_args()
    main(args.csv_path)
