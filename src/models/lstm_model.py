"""
lstm_model.py -- LSTM sequence autoencoder for detecting
shuffle (order-permutation) anti-forensic attacks in Windows Event Logs.

Input: Parsed log DataFrame in stored order per source_file.
Detects: Shuffle attacks (permuted row sequences, inverted timestamps, broken record IDs).
Saves to: models_saved/lstm_ae.keras and models_saved/lstm_meta.pkl
"""
import os
import pickle
import time
from typing import Dict, List, Optional, Tuple, Any

import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view
import sklearn.metrics as metrics

# Suppress verbose TF logs
os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '2')
os.environ.setdefault('TF_ENABLE_ONEDNN_OPTS', '0')

try:
    import tensorflow as tf
    import keras
    HAS_TF = True
except ImportError:
    tf = None
    keras = None
    HAS_TF = False

MODEL_SAVE_PATH = 'models_saved/lstm_ae.keras'
META_SAVE_PATH = 'models_saved/lstm_meta.pkl'
WINDOW_SIZE = 10
CONT_FEATURES = ['f_dt', 'f_rid', 'hour']


def build_features(
        df: pd.DataFrame,
        id_map: Optional[Dict[int, int]] = None
) -> Tuple[pd.DataFrame, Dict[int, int]]:
    """
    Extract continuous and discrete sequence features in stored file order.
    Never sorts rows, preserving chronological / physical order for shuffle detection.

    Parameters:
        df (pd.DataFrame): Raw or parsed event log DataFrame.
        id_map (Optional[Dict[int, int]]): Mapping from event_id to integer index.

    Returns:
        Tuple[pd.DataFrame, Dict[int, int]]: Feature-enriched DataFrame and id_map.

    Time Complexity: O(n) where n is total rows.
    Space Complexity: O(n) for feature arrays.
    """
    df_out = df.copy()

    # Time parsing and hour fraction
    time_created = pd.to_datetime(df_out['time_created'], utc=True, errors='coerce')
    hours = (time_created.dt.hour / 23.0).fillna(0.0).values

    # Source file boundary detection
    if 'source_file' in df_out.columns:
        source_files = df_out['source_file'].astype(str).values
        is_new_file = np.concatenate(([True], source_files[1:] != source_files[:-1]))
    else:
        is_new_file = np.zeros(len(df_out), dtype=bool)
        if len(is_new_file) > 0:
            is_new_file[0] = True

    # dt calculation (seconds between consecutive rows in file)
    time_sec = time_created.astype('int64') // 10**9
    dt = np.diff(time_sec, prepend=time_sec.iloc[0] if len(time_sec) > 0 else 0).astype(float)
    dt[is_new_file] = 0.0

    # rid_gap calculation (record id diff - 1)
    if 'event_record_id' in df_out.columns:
        rids = pd.to_numeric(df_out['event_record_id'], errors='coerce').fillna(0).values.astype(float)
        rid_diff = np.diff(rids, prepend=rids[0] if len(rids) > 0 else 0)
        rid_gap = rid_diff - 1.0
        rid_gap[is_new_file] = 0.0
    else:
        rid_gap = np.zeros(len(df_out), dtype=float)

    # Sign-preserving log1p transforms
    f_dt = np.sign(dt) * np.log1p(np.abs(dt))
    f_rid = np.sign(rid_gap) * np.log1p(np.abs(rid_gap))

    # Event ID embedding map
    raw_eids = pd.to_numeric(df_out['event_id'], errors='coerce').fillna(0).astype(int).values
    if id_map is None:
        if 'attack_type' in df_out.columns:
            normal_mask = (df_out['attack_type'] == 'normal').values
            normal_eids = np.unique(raw_eids[normal_mask])
        else:
            normal_eids = np.unique(raw_eids)
        sorted_eids = sorted([int(e) for e in normal_eids if e > 0])
        id_map = {eid: idx for idx, eid in enumerate(sorted_eids, start=1)}

    mapped_eids = np.array([id_map.get(int(e), 0) for e in raw_eids], dtype=np.int32)

    df_out['f_dt'] = f_dt
    df_out['f_rid'] = f_rid
    df_out['hour'] = hours
    df_out['eid'] = mapped_eids

    return df_out, id_map


def make_windows(
        df: pd.DataFrame,
        W: int = WINDOW_SIZE
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[Tuple[str, int, int]]]:
    """
    Generate sliding sequences of length W per source_file.
    Excludes windows containing critical_event records.

    Parameters:
        df (pd.DataFrame): DataFrame with engineered features.
        W (int): Window size (default: 10).

    Returns:
        Tuple[np.ndarray, np.ndarray, np.ndarray, List[Tuple[str, int, int]]]:
            - X_cont: Continuous features array (N_windows, W, 3)
            - X_eid: Discrete event ID array (N_windows, W)
            - y_win: Window shuffle binary labels (N_windows,)
            - win_meta: Metadata list of (source_file, start_row, end_row)

    Time Complexity: O(n * W)
    Space Complexity: O(n * W)
    """
    cont_list: List[np.ndarray] = []
    eid_list: List[np.ndarray] = []
    y_list: List[np.ndarray] = []
    meta_list: List[Tuple[str, int, int]] = []

    if 'source_file' in df.columns:
        grouped = df.groupby('source_file', sort=False)
    else:
        grouped = [('single_file', df)]

    for src_name, group in grouped:
        n_rows = len(group)
        if n_rows < W:
            continue

        cont_vals = group[CONT_FEATURES].values.astype(np.float32)
        eid_vals = group['eid'].values.astype(np.int32)

        # Critical event mask (to exclude windows with critical events)
        if 'attack_type' in group.columns:
            crit_mask = (group['attack_type'] == 'critical_event').values
            shuf_mask = (group['attack_type'] == 'shuffle').values
        else:
            is_crit = (
                group.get('is_critical_event', 0) == 1
                if 'is_critical_event' in group.columns
                else group['event_id'].isin([1102, 4719]).values
            )
            crit_mask = is_crit
            shuf_mask = (group.get('is_tampered', 0) == 1).values

        c_wins = sliding_window_view(cont_vals, window_shape=(W, len(CONT_FEATURES))).squeeze(axis=1)
        e_wins = sliding_window_view(eid_vals, window_shape=W)
        crit_wins = sliding_window_view(crit_mask, window_shape=W).any(axis=1)
        shuf_wins = sliding_window_view(shuf_mask, window_shape=W).any(axis=1).astype(int)

        valid_indices = np.where(~crit_wins)[0]
        if len(valid_indices) == 0:
            continue

        cont_list.append(c_wins[valid_indices])
        eid_list.append(e_wins[valid_indices])
        y_list.append(shuf_wins[valid_indices])

        for v_idx in valid_indices:
            meta_list.append((str(src_name), int(v_idx), int(v_idx + W)))

    if cont_list:
        X_cont = np.concatenate(cont_list, axis=0)
        X_eid = np.concatenate(eid_list, axis=0)
        y_win = np.concatenate(y_list, axis=0)
    else:
        X_cont = np.empty((0, W, len(CONT_FEATURES)), dtype=np.float32)
        X_eid = np.empty((0, W), dtype=np.int32)
        y_win = np.empty(0, dtype=int)

    return X_cont, X_eid, y_win, meta_list


def build_model(
        n_ids: int,
        W: int = WINDOW_SIZE,
        cont_dim: int = len(CONT_FEATURES)
) -> Any:
    """
    Construct Keras LSTM Autoencoder architecture.
    Concatenates Event ID embeddings with continuous dynamics features.

    Parameters:
        n_ids (int): Vocabulary size for event ID embedding layer.
        W (int): Window sequence length.
        cont_dim (int): Number of continuous features per step.

    Returns:
        keras.Model: Compiled Keras LSTM Autoencoder model.

    Time Complexity: O(1) model initialization.
    Space Complexity: O(params) for network weights.
    """
    eid_input = keras.Input(shape=(W,), dtype='int32', name='eid_in')
    cont_input = keras.Input(shape=(W, cont_dim), dtype='float32', name='cont_in')

    # Embedding for discrete event IDs
    eid_embed = keras.layers.Embedding(
        input_dim=max(n_ids + 1, 2),
        output_dim=8,
        name='eid_embed'
    )(eid_input)

    # Merge embedded event ID sequence with continuous dynamics
    merged = keras.layers.Concatenate(axis=-1, name='merged_features')([eid_embed, cont_input])

    # Encoder
    encoded = keras.layers.LSTM(32, return_sequences=False, name='encoder_lstm')(merged)

    # Decoder bridge
    repeated = keras.layers.RepeatVector(W, name='repeat_bridge')(encoded)
    decoded = keras.layers.LSTM(32, return_sequences=True, name='decoder_lstm')(repeated)

    # Reconstruction output layer (reconstructs continuous features)
    outputs = keras.layers.TimeDistributed(
        keras.layers.Dense(cont_dim),
        name='reconstructed_cont'
    )(decoded)

    model = keras.Model(inputs=[eid_input, cont_input], outputs=outputs, name='lstm_autoencoder')
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=0.001), loss='mse')
    return model


_BaseCallback = keras.callbacks.Callback if (HAS_TF and keras is not None) else object


class EpochTimerCallback(_BaseCallback):
    """Callback to print execution time and loss per epoch."""

    def on_epoch_begin(self, epoch, logs=None):
        self.epoch_start = time.time()

    def on_epoch_end(self, epoch, logs=None):
        duration = time.time() - self.epoch_start
        train_loss = logs.get('loss', 0.0)
        val_loss = logs.get('val_loss', 0.0)
        print(f"Epoch {epoch+1:02d} | Train MSE: {train_loss:.6f} | Val MSE: {val_loss:.6f} | Time: {duration:.2f}s")


def train(
        csv_path: str,
        model_save_path: str = MODEL_SAVE_PATH,
        meta_save_path: str = META_SAVE_PATH,
        max_epochs: int = 15,
        batch_size: int = 256
) -> Dict[str, Any]:
    """
    Train LSTM Autoencoder on normal windows from specified dataset.

    Parameters:
        csv_path (str): Path to shuffle attacks labeled CSV dataset.
        model_save_path (str): Destination for serialized .keras model.
        meta_save_path (str): Destination for metadata pickle.
        max_epochs (int): Maximum training epochs (default 15).
        batch_size (int): Mini-batch size (default 256).

    Returns:
        Dict[str, Any]: Training summary, threshold, and validation metrics.

    Time Complexity: O(epochs * N_train_windows)
    Space Complexity: O(N_windows * W)
    """
    print("=" * 60)
    print("LOGSHIELD LSTM AUTOENCODER TRAINING")
    print("=" * 60)
    print(f"Loading dataset from: {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df):,} total log entries across {df['source_file'].nunique()} files.")

    # Feature enrichment and ID mapping
    df_feat, id_map = build_features(df)
    n_ids = len(id_map)
    print(f"Created event ID embedding vocabulary with {n_ids} distinct normal Event IDs.")

    # Dataset partition by source_file
    TEST_FILES = [
        'Security_bulkvolume3.evtx',
        'Security_manual4.evtx'
    ]
    VAL_FILES = [
        'Security_manual2.evtx',
        'Security_part3_20260831_043735.evtx',
        'Security_20260825_125616.evtx'
    ]

    all_files = df['source_file'].unique().tolist()
    TRAIN_FILES = [f for f in all_files if f not in TEST_FILES and f not in VAL_FILES]

    train_df = df_feat[df_feat['source_file'].isin(TRAIN_FILES)].copy()
    val_df = df_feat[df_feat['source_file'].isin(VAL_FILES)].copy()
    test_df = df_feat[df_feat['source_file'].isin(TEST_FILES)].copy()

    # Create sliding windows
    X_train_c, X_train_e, y_train, _ = make_windows(train_df, W=WINDOW_SIZE)
    X_val_c, X_val_e, y_val, _ = make_windows(val_df, W=WINDOW_SIZE)
    X_test_c, X_test_e, y_test, _ = make_windows(test_df, W=WINDOW_SIZE)

    print("\nDataset Split Summary (Windows):")
    print(f"  TRAIN: {len(y_train):,} windows ({np.sum(y_train==0):,} normal, {np.sum(y_train==1):,} shuffle)")
    print(f"  VAL:   {len(y_val):,} windows ({np.sum(y_val==0):,} normal, {np.sum(y_val==1):,} shuffle)")
    print(f"  TEST:  {len(y_test):,} windows ({np.sum(y_test==0):,} normal, {np.sum(y_test==1):,} shuffle)")

    if len(y_val) == 0 or np.sum(y_val == 1) == 0:
        raise ValueError("Validation set does not contain any shuffle attack windows!")
    if len(y_test) == 0 or np.sum(y_test == 1) == 0:
        raise ValueError("Test set does not contain any shuffle attack windows!")

    # Autoencoder trains exclusively on normal windows
    train_normal_idx = np.where(y_train == 0)[0]
    val_normal_idx = np.where(y_val == 0)[0]

    X_train_c_norm = X_train_c[train_normal_idx]
    X_train_e_norm = X_train_e[train_normal_idx]

    X_val_c_norm = X_val_c[val_normal_idx]
    X_val_e_norm = X_val_e[val_normal_idx]

    print(f"\nTraining on {len(X_train_c_norm):,} NORMAL windows...")

    # Build model
    model = build_model(n_ids=n_ids, W=WINDOW_SIZE, cont_dim=len(CONT_FEATURES))

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=3,
            restore_best_weights=True,
            verbose=1
        ),
        EpochTimerCallback()
    ]

    t_start = time.time()
    history = model.fit(
        x=[X_train_e_norm, X_train_c_norm],
        y=X_train_c_norm,
        validation_data=([X_val_e_norm, X_val_c_norm], X_val_c_norm),
        epochs=max_epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=0
    )
    total_train_time = time.time() - t_start
    print(f"Training completed in {total_train_time:.2f}s.")

    # Threshold Selection on Validation Set
    print("\nCalibrating anomaly detection threshold on Validation Set...")
    val_pred = model.predict([X_val_e, X_val_c], batch_size=512, verbose=0)
    val_mse = np.mean((val_pred - X_val_c)**2, axis=(1, 2))

    # Search best threshold for F1 on VAL
    candidate_percentiles = np.linspace(80.0, 99.9, 200)
    candidate_thresholds = np.percentile(val_mse[y_val == 0], candidate_percentiles)

    best_f1 = -1.0
    best_thr = candidate_thresholds[0]
    best_p = 0.0
    best_r = 0.0

    for thr in candidate_thresholds:
        preds = (val_mse > thr).astype(int)
        f1 = metrics.f1_score(y_val, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_thr = thr
            best_p = metrics.precision_score(y_val, preds, zero_division=0)
            best_r = metrics.recall_score(y_val, preds, zero_division=0)

    print(f"Optimal Threshold (VAL): {best_thr:.6f}")
    print(f"VAL Performance: Precision={best_p:.4f}, Recall={best_r:.4f}, F1={best_f1:.4f}")

    # Save artifacts
    os.makedirs(os.path.dirname(os.path.abspath(model_save_path)), exist_ok=True)
    model.save(model_save_path)

    meta = {
        'id_map': id_map,
        'threshold': float(best_thr),
        'window_size': WINDOW_SIZE,
        'continuous_features': CONT_FEATURES,
        'val_precision': float(best_p),
        'val_recall': float(best_r),
        'val_f1': float(best_f1),
        'tf_version': tf.__version__,
        'keras_version': keras.__version__
    }

    with open(meta_save_path, 'wb') as f:
        pickle.dump(meta, f)

    print(f"Saved model to: {model_save_path}")
    print(f"Saved metadata to: {meta_save_path}")

    return {
        'model': model,
        'meta': meta,
        'test_df': test_df,
        'history': history.history
    }


def evaluate(
        test_df: pd.DataFrame,
        model: Optional[Any] = None,
        meta: Optional[Dict[str, Any]] = None,
        model_path: str = MODEL_SAVE_PATH,
        meta_path: str = META_SAVE_PATH
) -> Dict[str, Any]:
    """
    Evaluate trained LSTM Autoencoder and baseline detectors on the TEST split.

    Parameters:
        test_df (pd.DataFrame): Test DataFrame containing log records.
        model (Optional[keras.Model]): In-memory model instance.
        meta (Optional[Dict[str, Any]]): In-memory metadata dictionary.
        model_path (str): Filepath to load model if not provided.
        meta_path (str): Filepath to load metadata if not provided.

    Returns:
        Dict[str, Any]: Evaluation metrics for LSTM-AE and Baselines.

    Time Complexity: O(N_test_windows * W)
    Space Complexity: O(N_test_windows * W)
    """
    if model is None or meta is None:
        model, meta = load_lstm(model_path, meta_path)

    # Ensure features are present
    if 'f_dt' not in test_df.columns or 'eid' not in test_df.columns:
        test_df, _ = build_features(test_df, id_map=meta['id_map'])

    W = meta.get('window_size', WINDOW_SIZE)
    threshold = meta['threshold']

    X_test_c, X_test_e, y_test, _ = make_windows(test_df, W=W)

    if len(y_test) == 0:
        raise ValueError("Test set contains 0 valid windows for evaluation!")

    # 1. LSTM Autoencoder Evaluation
    t0 = time.time()
    test_pred = model.predict([X_test_e, X_test_c], batch_size=512, verbose=0)
    lstm_inference_time = time.time() - t0
    test_mse = np.mean((test_pred - X_test_c)**2, axis=(1, 2))
    y_pred_lstm = (test_mse > threshold).astype(int)

    lstm_p = metrics.precision_score(y_test, y_pred_lstm, zero_division=0)
    lstm_r = metrics.recall_score(y_test, y_pred_lstm, zero_division=0)
    lstm_f1 = metrics.f1_score(y_test, y_pred_lstm, zero_division=0)

    # 2. Rule Baseline Evaluation (rid_gap != 0 or dt < 0 in window)
    dt_raw = X_test_c[:, :, 0]   # f_dt < 0 implies dt < 0
    rid_raw = X_test_c[:, :, 1]  # f_rid != 0 implies rid_gap != 0
    y_pred_rule = ((dt_raw < 0) | (rid_raw != 0)).any(axis=1).astype(int)

    rule_p = metrics.precision_score(y_test, y_pred_rule, zero_division=0)
    rule_r = metrics.recall_score(y_test, y_pred_rule, zero_division=0)
    rule_f1 = metrics.f1_score(y_test, y_pred_rule, zero_division=0)

    # 3. Isolation Forest Baseline (if available)
    if_p, if_r, if_f1 = 0.0, 0.0, 0.0
    if os.path.exists('models_saved/isolation_forest.pkl'):
        try:
            from src.models.isolation_forest import predict_anomalies
            from src.features import extract_features

            if_df = test_df.copy()
            if_df['time_created'] = pd.to_datetime(if_df['time_created'], utc=True)
            if_df = extract_features(if_df)
            if_df = predict_anomalies(if_df, 'models_saved/isolation_forest.pkl')

            # Map IF flags to test windows
            if 'source_file' in if_df.columns:
                grouped = if_df.groupby('source_file', sort=False)
            else:
                grouped = [('single', if_df)]

            if_win_preds = []
            for _, g in grouped:
                if len(g) < W:
                    continue
                flags = g['if_flag'].values
                crit = (g.get('attack_type', '') == 'critical_event').values if 'attack_type' in g.columns else (g.get('is_critical_event', 0) == 1).values
                f_wins = sliding_window_view(flags, window_shape=W).any(axis=1).astype(int)
                cr_wins = sliding_window_view(crit, window_shape=W).any(axis=1)
                valid = ~cr_wins
                if_win_preds.append(f_wins[valid])

            if if_win_preds:
                y_pred_if = np.concatenate(if_win_preds, axis=0)
                if len(y_pred_if) == len(y_test):
                    if_p = metrics.precision_score(y_test, y_pred_if, zero_division=0)
                    if_r = metrics.recall_score(y_test, y_pred_if, zero_division=0)
                    if_f1 = metrics.f1_score(y_test, y_pred_if, zero_division=0)
        except Exception:
            pass

    results = {
        'total_test_windows': int(len(y_test)),
        'shuffle_windows': int(np.sum(y_test == 1)),
        'normal_windows': int(np.sum(y_test == 0)),
        'lstm_precision': float(lstm_p),
        'lstm_recall': float(lstm_r),
        'lstm_f1': float(lstm_f1),
        'rule_precision': float(rule_p),
        'rule_recall': float(rule_r),
        'rule_f1': float(rule_f1),
        'if_precision': float(if_p),
        'if_recall': float(if_r),
        'if_f1': float(if_f1),
        'inference_time_sec': float(lstm_inference_time)
    }

    print("\n" + "=" * 60)
    print("TEST EVALUATION RESULTS (Shuffle Attack Detection)")
    print("=" * 60)
    print(f"{'Model':<25} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10}")
    print("-" * 60)
    print(f"{'LSTM Autoencoder (Ours)':<25} | {lstm_p:<10.4f} | {lstm_r:<10.4f} | {lstm_f1:<10.4f}")
    print(f"{'Rule Baseline (dt<0/gap)':<25} | {rule_p:<10.4f} | {rule_r:<10.4f} | {rule_f1:<10.4f}")
    if if_f1 > 0:
        print(f"{'Isolation Forest':<25} | {if_p:<10.4f} | {if_r:<10.4f} | {if_f1:<10.4f}")
    print("=" * 60)

    return results


def load_lstm(
        model_path: str = MODEL_SAVE_PATH,
        meta_path: str = META_SAVE_PATH
) -> Tuple[Any, Dict[str, Any]]:
    """
    Load serialized LSTM model and metadata.
    Fails closed with a generic exception without leaking internal system traces.

    Parameters:
        model_path (str): Filepath to serialized .keras model.
        meta_path (str): Filepath to serialized metadata pickle.

    Returns:
        Tuple[Any, Dict[str, Any]]: Loaded model and metadata dict.

    Time Complexity: O(1) loading time.
    Space Complexity: O(model_size) in memory.
    """
    if not HAS_TF or keras is None:
        raise RuntimeError(
            "LogShield LSTM model unavailable: TensorFlow/Keras is not installed in the current environment."
        )

    if not os.path.exists(model_path):
        raise RuntimeError(
            f"LogShield LSTM model unavailable: model file not found at '{model_path}'. "
            "Please train or provide the model file."
        )

    if not os.path.exists(meta_path):
        raise RuntimeError(
            f"LogShield LSTM metadata unavailable: metadata file not found at '{meta_path}'. "
            "Please train or provide the metadata file."
        )

    try:
        model = keras.models.load_model(model_path, compile=False)
        with open(meta_path, 'rb') as f:
            meta = pickle.load(f)
        return model, meta
    except Exception as e:
        raise RuntimeError(
            "LogShield LSTM model unavailable: failed to load model or metadata due to corruption or format incompatibility."
        ) from None


def predict_lstm(
        df: pd.DataFrame,
        model: Optional[Any] = None,
        meta: Optional[Dict[str, Any]] = None,
        model_path: str = MODEL_SAVE_PATH,
        meta_path: str = META_SAVE_PATH
) -> pd.DataFrame:
    """
    Score event log DataFrame for sequence shuffle attacks.
    Preserves original log order and calculates window reconstruction errors.

    Parameters:
        df (pd.DataFrame): Input DataFrame in stored file order.
        model (Optional[Any]): Pre-loaded model (optional).
        meta (Optional[Dict[str, Any]]): Pre-loaded metadata (optional).
        model_path (str): Filepath to model if not pre-loaded.
        meta_path (str): Filepath to metadata if not pre-loaded.

    Returns:
        pd.DataFrame: DataFrame enriched with lstm_flag and lstm_score columns.

    Time Complexity: O(n * W)
    Space Complexity: O(n)
    """
    df_out = df.copy()

    if not HAS_TF or keras is None:
        df_out['lstm_flag'] = 0
        df_out['lstm_score'] = 0.0
        return df_out

    if model is None or meta is None:
        model, meta = load_lstm(model_path=model_path, meta_path=meta_path)

    W = meta.get('window_size', WINDOW_SIZE)
    threshold = meta.get('threshold', 0.1)
    id_map = meta.get('id_map', {})

    n_total = len(df_out)
    if n_total == 0:
        df_out['lstm_flag'] = pd.Series(dtype=int)
        df_out['lstm_score'] = pd.Series(dtype=float)
        return df_out

    # Initialize columns
    lstm_scores = np.zeros(n_total, dtype=np.float32)

    df_feat, _ = build_features(df_out, id_map=id_map)

    # Process each source_file
    if 'source_file' in df_feat.columns:
        groups = df_feat.groupby('source_file', sort=False)
    else:
        groups = [('single_file', df_feat)]

    for _, group in groups:
        n_rows = len(group)
        if n_rows < W:
            continue

        indices = group.index.values
        cont_vals = group[CONT_FEATURES].values.astype(np.float32)
        eid_vals = group['eid'].values.astype(np.int32)

        c_wins = sliding_window_view(cont_vals, window_shape=(W, len(CONT_FEATURES))).squeeze(axis=1)
        e_wins = sliding_window_view(eid_vals, window_shape=W)

        preds = model.predict([e_wins, c_wins], batch_size=512, verbose=0)
        win_mse = np.mean((preds - c_wins)**2, axis=(1, 2))

        # Map window MSE scores back to row maximums
        for i, mse_val in enumerate(win_mse):
            row_slice = indices[i : i + W]
            lstm_scores[row_slice] = np.maximum(lstm_scores[row_slice], mse_val)

    df_out['lstm_score'] = lstm_scores.astype(float)
    df_out['lstm_flag'] = (lstm_scores > threshold).astype(int)

    return df_out
