#!/usr/bin/env python3
"""
AI Security App - LSTM/GRU Prediction Script
=============================================

Chạy inference trên LSTM/GRU AutoEncoder model.
Nhận chuỗi L Summary Vectors và trả về anomaly score.

Usage:
    # Via command line
    python predict.py --model model.pth --sequence "[[f1,f2,...f15], [f1,f2,...f15], ...]"

    # Via stdin (from Rust)
    echo '{"sequence": [[...],...], "model_path": "model.pth"}' | python predict.py --stdin

Output (JSON):
    {"score": 0.75, "is_anomaly": true, "confidence": 0.85, "raw_mse": 0.0234}
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import List, Optional, Tuple
import numpy as np

try:
    import torch
    import torch.nn as nn
except ImportError:
    print(json.dumps({"error": "PyTorch not installed", "score": 0.0, "is_anomaly": False}))
    sys.exit(1)


# ============================================================================
# CONSTANTS (phải match với train.py)
# ============================================================================

FEATURE_COUNT = 15
DEFAULT_SEQUENCE_LENGTH = 5
DEFAULT_THRESHOLD = 0.7


# ============================================================================
# MODEL DEFINITIONS (copy từ train.py để standalone)
# ============================================================================

class LSTMEncoder(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, latent_dim: int, num_layers: int):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.fc_latent = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x):
        output, (hidden, cell) = self.lstm(x)
        latent = self.fc_latent(hidden[-1])
        return latent, (hidden, cell)


class LSTMDecoder(nn.Module):
    def __init__(self, latent_dim: int, hidden_dim: int, output_dim: int,
                 num_layers: int, sequence_length: int):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length

        self.fc_hidden = nn.Linear(latent_dim, hidden_dim * num_layers)
        self.fc_cell = nn.Linear(latent_dim, hidden_dim * num_layers)

        self.lstm = nn.LSTM(
            input_size=latent_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.fc_output = nn.Linear(hidden_dim, output_dim)

    def forward(self, latent, sequence_length: int = None):
        if sequence_length is None:
            sequence_length = self.sequence_length

        batch_size = latent.size(0)

        hidden = self.fc_hidden(latent).view(self.num_layers, batch_size, self.hidden_dim)
        cell = self.fc_cell(latent).view(self.num_layers, batch_size, self.hidden_dim)

        decoder_input = latent.unsqueeze(1).repeat(1, sequence_length, 1)
        output, _ = self.lstm(decoder_input, (hidden, cell))
        reconstructed = self.fc_output(output)

        return reconstructed


class LSTMAutoEncoder(nn.Module):
    def __init__(self, input_dim: int = FEATURE_COUNT,
                 hidden_dim: int = 64,
                 latent_dim: int = 32,
                 num_layers: int = 2,
                 sequence_length: int = DEFAULT_SEQUENCE_LENGTH):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length

        self.encoder = LSTMEncoder(input_dim, hidden_dim, latent_dim, num_layers)
        self.decoder = LSTMDecoder(latent_dim, hidden_dim, input_dim, num_layers, sequence_length)

    def forward(self, x):
        latent, _ = self.encoder(x)
        reconstructed = self.decoder(latent, x.size(1))
        return reconstructed

    def get_reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
        return mse


class GRUAutoEncoder(nn.Module):
    def __init__(self, input_dim: int = FEATURE_COUNT,
                 hidden_dim: int = 64,
                 latent_dim: int = 32,
                 num_layers: int = 2,
                 sequence_length: int = DEFAULT_SEQUENCE_LENGTH):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length

        self.encoder_gru = nn.GRU(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.fc_latent = nn.Linear(hidden_dim, latent_dim)

        self.fc_hidden = nn.Linear(latent_dim, hidden_dim * num_layers)
        self.decoder_gru = nn.GRU(
            input_size=latent_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.fc_output = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        batch_size = x.size(0)
        seq_len = x.size(1)

        _, hidden = self.encoder_gru(x)
        latent = self.fc_latent(hidden[-1])

        decoder_hidden = self.fc_hidden(latent).view(self.num_layers, batch_size, self.hidden_dim)
        decoder_input = latent.unsqueeze(1).repeat(1, seq_len, 1)
        output, _ = self.decoder_gru(decoder_input, decoder_hidden)
        reconstructed = self.fc_output(output)

        return reconstructed

    def get_reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
        return mse


# ============================================================================
# MODEL LOADING
# ============================================================================

def load_model(model_path: str) -> Tuple[nn.Module, dict, float, dict]:
    """
    Load model từ file.

    Returns:
        (model, config, threshold, normalization)
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)

    model_type = checkpoint.get('model_type', 'lstm')
    config = checkpoint.get('config', {})
    threshold = checkpoint.get('threshold', DEFAULT_THRESHOLD)
    normalization = checkpoint.get('normalization', {'min_vals': [0]*FEATURE_COUNT,
                                                      'max_vals': [1]*FEATURE_COUNT})

    # Create model
    ModelClass = LSTMAutoEncoder if model_type == 'lstm' else GRUAutoEncoder
    model = ModelClass(
        input_dim=config.get('input_dim', FEATURE_COUNT),
        hidden_dim=config.get('hidden_dim', 64),
        latent_dim=config.get('latent_dim', 32),
        num_layers=config.get('num_layers', 2),
        sequence_length=config.get('sequence_length', DEFAULT_SEQUENCE_LENGTH),
    )

    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()

    return model, config, threshold, normalization


# ============================================================================
# PREDICTION
# ============================================================================

def normalize_sequence(sequence: np.ndarray, min_vals: List[float],
                        max_vals: List[float]) -> np.ndarray:
    """Normalize sequence với min/max từ training."""
    min_arr = np.array(min_vals)
    max_arr = np.array(max_vals)

    range_arr = max_arr - min_arr
    range_arr[range_arr == 0] = 1

    normalized = (sequence - min_arr) / range_arr
    return np.clip(normalized, 0, 1)


def predict_anomaly(model: nn.Module, sequence: np.ndarray,
                    threshold: float, config: dict) -> dict:
    """
    Chạy prediction trên một sequence.

    Args:
        model: Loaded model
        sequence: numpy array (L, F) - L timesteps, F features
        threshold: Anomaly threshold
        config: Model config

    Returns:
        dict với score, is_anomaly, confidence, raw_mse
    """
    expected_length = config.get('sequence_length', DEFAULT_SEQUENCE_LENGTH)

    # Validate sequence shape
    if len(sequence.shape) != 2:
        return {"error": f"Invalid sequence shape: {sequence.shape}. Expected (L, F)"}

    if sequence.shape[1] != FEATURE_COUNT:
        return {"error": f"Invalid features: {sequence.shape[1]}. Expected {FEATURE_COUNT}"}

    # Pad or truncate sequence if needed
    if sequence.shape[0] < expected_length:
        # Pad with last value
        padding = np.repeat(sequence[-1:], expected_length - sequence.shape[0], axis=0)
        sequence = np.vstack([sequence, padding])
    elif sequence.shape[0] > expected_length:
        # Take last L values
        sequence = sequence[-expected_length:]

    # Convert to tensor
    x = torch.FloatTensor(sequence).unsqueeze(0)  # (1, L, F)

    # Get reconstruction error
    with torch.no_grad():
        mse = model.get_reconstruction_error(x).item()

    # Calculate score (normalized to 0-1)
    # Higher MSE = higher anomaly score
    # Use sigmoid-like scaling
    score = min(1.0, mse / (threshold * 2))

    # Confidence based on how far from threshold
    distance_from_threshold = abs(mse - threshold) / threshold
    confidence = min(1.0, 0.5 + distance_from_threshold * 0.5)

    is_anomaly = mse > threshold

    return {
        "score": float(score),
        "is_anomaly": bool(is_anomaly),
        "confidence": float(confidence),
        "raw_mse": float(mse),
        "threshold": float(threshold),
    }


def predict_batch(model: nn.Module, sequences: List[np.ndarray],
                  threshold: float, config: dict) -> List[dict]:
    """Predict cho nhiều sequences."""
    results = []
    for seq in sequences:
        result = predict_anomaly(model, seq, threshold, config)
        results.append(result)
    return results


# ============================================================================
# SIMPLE FALLBACK (no model)
# ============================================================================

def simple_predict(sequence: np.ndarray) -> dict:
    """
    Rule-based prediction khi không có model.
    Sử dụng heuristics đơn giản.
    """
    if len(sequence.shape) != 2:
        return {"error": "Invalid sequence", "score": 0.0, "is_anomaly": False}

    # Thresholds cho 15 features
    thresholds = [
        50.0,   # 0: avg_cpu
        80.0,   # 1: max_cpu
        500.0,  # 2: avg_memory
        1000.0, # 3: max_memory
        15.0,   # 4: net_sent (log)
        15.0,   # 5: net_recv (log)
        10.0,   # 6: disk_read (log)
        10.0,   # 7: disk_write (log)
        100.0,  # 8: unique_processes
        0.9,    # 9: network_ratio
        0.2,    # 10: cpu_spike_rate
        0.2,    # 11: memory_spike_rate
        0.3,    # 12: new_process_rate
        10.0,   # 13: disk_io_rate
        1.0,    # 14: churn_rate
    ]

    anomaly_count = 0
    max_excess = 0.0

    # Check last timestep
    last_values = sequence[-1]

    for i, val in enumerate(last_values):
        if i < len(thresholds) and val > thresholds[i]:
            anomaly_count += 1
            excess = (val - thresholds[i]) / thresholds[i]
            max_excess = max(max_excess, excess)

    # Check trends (tăng liên tục)
    if len(sequence) > 1:
        trends = sequence[-1] - sequence[0]
        increasing = np.sum(trends > 0)
        if increasing > FEATURE_COUNT * 0.7:
            anomaly_count += 2

    score = min(1.0, anomaly_count / 10 + max_excess * 0.3)

    return {
        "score": float(score),
        "is_anomaly": score > 0.6,
        "confidence": 0.5,
        "raw_mse": None,
        "method": "heuristic",
    }


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='LSTM/GRU Anomaly Prediction')

    parser.add_argument('--model', type=str, help='Path to model file')
    parser.add_argument('--sequence', type=str, help='Sequence as JSON array [[f1,...,f15], ...]')
    parser.add_argument('--features', type=str, help='Single vector (legacy mode)')
    parser.add_argument('--stdin', action='store_true', help='Read input from stdin')
    parser.add_argument('--output', type=str, default='-', help='Output: - for stdout, path for file')

    args = parser.parse_args()

    result = {"score": 0.0, "is_anomaly": False, "confidence": 0.0}

    try:
        # Get input
        if args.stdin:
            input_data = json.loads(sys.stdin.read())
            model_path = input_data.get('model_path', args.model)
            sequence_data = input_data.get('sequence')
        elif args.sequence:
            sequence_data = json.loads(args.sequence)
            model_path = args.model
        elif args.features:
            # Legacy single-vector mode
            features = [float(x) for x in args.features.split(',')]
            sequence_data = [features]  # Convert to sequence of 1
            model_path = args.model
        else:
            result = {"error": "No input provided", "score": 0.0, "is_anomaly": False}
            print(json.dumps(result))
            return

        # Convert to numpy
        sequence = np.array(sequence_data, dtype=np.float32)

        # Ensure 2D
        if len(sequence.shape) == 1:
            sequence = sequence.reshape(1, -1)

        # Load model and predict
        if model_path and os.path.exists(model_path):
            model, config, threshold, normalization = load_model(model_path)

            # Normalize
            sequence = normalize_sequence(
                sequence,
                normalization.get('min_vals', [0]*FEATURE_COUNT),
                normalization.get('max_vals', [1]*FEATURE_COUNT)
            )

            result = predict_anomaly(model, sequence, threshold, config)
        else:
            # Fallback to heuristic
            result = simple_predict(sequence)
            result['warning'] = 'Model not found, using heuristic'

    except Exception as e:
        result = {
            "error": str(e),
            "score": 0.0,
            "is_anomaly": False,
            "confidence": 0.0,
        }

    # Output
    output_json = json.dumps(result)

    if args.output == '-':
        print(output_json)
    else:
        with open(args.output, 'w') as f:
            f.write(output_json)


if __name__ == '__main__':
    main()
