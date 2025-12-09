#!/usr/bin/env python3
"""
AI Security App - LSTM AutoEncoder Training Script
===================================================

Huấn luyện mô hình LSTM AutoEncoder để phát hiện anomaly trong chuỗi
Summary Vectors (time series anomaly detection).

Architecture:
- Input: Sequence of L Summary Vectors (L × 15 features)
- Encoder: LSTM layers compress to latent representation
- Decoder: LSTM layers reconstruct the sequence
- Loss: Reconstruction Error (MSE)

Usage:
    python train.py --data logs.json --output model.pth --sequence-length 5
"""

import argparse
import json
import sys
import os
from pathlib import Path
from datetime import datetime
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import Dataset, DataLoader
except ImportError:
    print("PyTorch chưa được cài đặt. Chạy: pip install torch")
    sys.exit(1)


# ============================================================================
# CONSTANTS
# ============================================================================

FEATURE_COUNT = 15           # Số features trong mỗi Summary Vector
DEFAULT_SEQUENCE_LENGTH = 5  # L = số Summary Vectors trong mỗi sequence
DEFAULT_HIDDEN_DIM = 64      # LSTM hidden dimension
DEFAULT_LATENT_DIM = 32      # Latent space dimension
DEFAULT_NUM_LAYERS = 2       # Số LSTM layers
DEFAULT_EPOCHS = 100
DEFAULT_BATCH_SIZE = 32
DEFAULT_LEARNING_RATE = 0.001
ANOMALY_THRESHOLD = 0.7      # Ngưỡng MSE để xác định anomaly


# ============================================================================
# DATASET
# ============================================================================

class SequenceDataset(Dataset):
    """Dataset cho chuỗi Summary Vectors."""

    def __init__(self, sequences: np.ndarray):
        """
        Args:
            sequences: numpy array shape (N, L, F)
                       N = số samples, L = sequence length, F = features
        """
        self.sequences = torch.FloatTensor(sequences)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.sequences[idx]  # Input = Target


def create_sequences(data: np.ndarray, sequence_length: int) -> np.ndarray:
    """
    Chuyển danh sách Summary Vectors thành các sequences.

    Args:
        data: numpy array shape (N, F) - N vectors, F features each
        sequence_length: L - độ dài mỗi sequence

    Returns:
        numpy array shape (N-L+1, L, F) - các overlapping sequences
    """
    sequences = []
    for i in range(len(data) - sequence_length + 1):
        seq = data[i:i + sequence_length]
        sequences.append(seq)
    return np.array(sequences)


def normalize_features(data: np.ndarray) -> tuple:
    """Chuẩn hóa features về [0, 1] range."""
    min_vals = data.min(axis=0)
    max_vals = data.max(axis=0)

    # Tránh chia cho 0
    range_vals = max_vals - min_vals
    range_vals[range_vals == 0] = 1

    normalized = (data - min_vals) / range_vals
    return normalized, min_vals, max_vals


# ============================================================================
# LSTM AUTOENCODER MODEL
# ============================================================================

class LSTMEncoder(nn.Module):
    """LSTM Encoder - Nén sequence thành latent representation."""

    def __init__(self, input_dim: int, hidden_dim: int, latent_dim: int, num_layers: int):
        super().__init__()

        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )

        # Project to latent space
        self.fc_latent = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x):
        # x: (batch, seq_len, input_dim)
        batch_size = x.size(0)

        # LSTM encoding
        output, (hidden, cell) = self.lstm(x)

        # Lấy hidden state cuối cùng
        # hidden: (num_layers, batch, hidden_dim)
        last_hidden = hidden[-1]  # (batch, hidden_dim)

        # Project to latent
        latent = self.fc_latent(last_hidden)  # (batch, latent_dim)

        return latent, (hidden, cell)


class LSTMDecoder(nn.Module):
    """LSTM Decoder - Reconstruct sequence từ latent."""

    def __init__(self, latent_dim: int, hidden_dim: int, output_dim: int,
                 num_layers: int, sequence_length: int):
        super().__init__()

        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length

        # Project from latent to hidden
        self.fc_hidden = nn.Linear(latent_dim, hidden_dim * num_layers)
        self.fc_cell = nn.Linear(latent_dim, hidden_dim * num_layers)

        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=latent_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )

        # Output projection
        self.fc_output = nn.Linear(hidden_dim, output_dim)

    def forward(self, latent, sequence_length: int = None):
        if sequence_length is None:
            sequence_length = self.sequence_length

        batch_size = latent.size(0)

        # Initialize hidden states from latent
        hidden = self.fc_hidden(latent).view(self.num_layers, batch_size, self.hidden_dim)
        cell = self.fc_cell(latent).view(self.num_layers, batch_size, self.hidden_dim)

        # Repeat latent as input for each timestep
        decoder_input = latent.unsqueeze(1).repeat(1, sequence_length, 1)

        # LSTM decoding
        output, _ = self.lstm(decoder_input, (hidden, cell))

        # Project to output dimension
        reconstructed = self.fc_output(output)  # (batch, seq_len, output_dim)

        return reconstructed


class LSTMAutoEncoder(nn.Module):
    """
    LSTM AutoEncoder cho Time Series Anomaly Detection.

    Architecture:
        Encoder: LSTM → Latent
        Decoder: Latent → LSTM → Reconstructed Sequence
    """

    def __init__(self, input_dim: int = FEATURE_COUNT,
                 hidden_dim: int = DEFAULT_HIDDEN_DIM,
                 latent_dim: int = DEFAULT_LATENT_DIM,
                 num_layers: int = DEFAULT_NUM_LAYERS,
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
        # x: (batch, seq_len, input_dim)
        latent, _ = self.encoder(x)
        reconstructed = self.decoder(latent, x.size(1))
        return reconstructed

    def encode(self, x):
        """Chỉ encoding - trả về latent representation."""
        latent, _ = self.encoder(x)
        return latent

    def get_reconstruction_error(self, x):
        """Tính reconstruction error (MSE) cho mỗi sample."""
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            # MSE per sample
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
        return mse


# ============================================================================
# GRU AUTOENCODER MODEL (Alternative)
# ============================================================================

class GRUAutoEncoder(nn.Module):
    """
    GRU AutoEncoder - Lighter alternative to LSTM.
    Same interface as LSTMAutoEncoder but uses GRU cells.
    """

    def __init__(self, input_dim: int = FEATURE_COUNT,
                 hidden_dim: int = DEFAULT_HIDDEN_DIM,
                 latent_dim: int = DEFAULT_LATENT_DIM,
                 num_layers: int = DEFAULT_NUM_LAYERS,
                 sequence_length: int = DEFAULT_SEQUENCE_LENGTH):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length

        # Encoder
        self.encoder_gru = nn.GRU(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.fc_latent = nn.Linear(hidden_dim, latent_dim)

        # Decoder
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

        # Encode
        _, hidden = self.encoder_gru(x)
        latent = self.fc_latent(hidden[-1])

        # Decode
        decoder_hidden = self.fc_hidden(latent).view(self.num_layers, batch_size, self.hidden_dim)
        decoder_input = latent.unsqueeze(1).repeat(1, seq_len, 1)
        output, _ = self.decoder_gru(decoder_input, decoder_hidden)
        reconstructed = self.fc_output(output)

        return reconstructed

    def encode(self, x):
        _, hidden = self.encoder_gru(x)
        return self.fc_latent(hidden[-1])

    def get_reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
        return mse


# ============================================================================
# TRAINING
# ============================================================================

def train_model(model: nn.Module, train_loader: DataLoader,
                val_loader: DataLoader = None,
                epochs: int = DEFAULT_EPOCHS,
                learning_rate: float = DEFAULT_LEARNING_RATE,
                device: str = 'cpu') -> dict:
    """
    Huấn luyện LSTM/GRU AutoEncoder.

    Returns:
        dict với training history và statistics
    """
    model = model.to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=10, factor=0.5)

    history = {
        'train_loss': [],
        'val_loss': [],
        'best_loss': float('inf'),
        'best_epoch': 0,
    }

    print(f"\n{'='*60}")
    print(f"Training {model.__class__.__name__}")
    print(f"Device: {device}")
    print(f"Epochs: {epochs}, LR: {learning_rate}")
    print(f"{'='*60}\n")

    for epoch in range(epochs):
        # Training
        model.train()
        train_losses = []

        for batch_x, batch_y in train_loader:
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)

            optimizer.zero_grad()
            output = model(batch_x)
            loss = criterion(output, batch_y)
            loss.backward()

            # Gradient clipping để tránh exploding gradients
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)

            optimizer.step()
            train_losses.append(loss.item())

        avg_train_loss = np.mean(train_losses)
        history['train_loss'].append(avg_train_loss)

        # Validation
        if val_loader:
            model.eval()
            val_losses = []
            with torch.no_grad():
                for batch_x, batch_y in val_loader:
                    batch_x = batch_x.to(device)
                    batch_y = batch_y.to(device)
                    output = model(batch_x)
                    loss = criterion(output, batch_y)
                    val_losses.append(loss.item())

            avg_val_loss = np.mean(val_losses)
            history['val_loss'].append(avg_val_loss)
            scheduler.step(avg_val_loss)

            if avg_val_loss < history['best_loss']:
                history['best_loss'] = avg_val_loss
                history['best_epoch'] = epoch

            if (epoch + 1) % 10 == 0 or epoch == 0:
                print(f"Epoch [{epoch+1:3d}/{epochs}] | "
                      f"Train Loss: {avg_train_loss:.6f} | "
                      f"Val Loss: {avg_val_loss:.6f}")
        else:
            if avg_train_loss < history['best_loss']:
                history['best_loss'] = avg_train_loss
                history['best_epoch'] = epoch

            if (epoch + 1) % 10 == 0 or epoch == 0:
                print(f"Epoch [{epoch+1:3d}/{epochs}] | Train Loss: {avg_train_loss:.6f}")

    print(f"\n{'='*60}")
    print(f"Training Complete!")
    print(f"Best Loss: {history['best_loss']:.6f} (Epoch {history['best_epoch']+1})")
    print(f"{'='*60}\n")

    return history


def calculate_threshold(model: nn.Module, data_loader: DataLoader,
                        percentile: float = 95, device: str = 'cpu') -> float:
    """Tính threshold từ reconstruction errors của normal data."""
    model.eval()
    all_errors = []

    with torch.no_grad():
        for batch_x, _ in data_loader:
            batch_x = batch_x.to(device)
            errors = model.get_reconstruction_error(batch_x)
            all_errors.extend(errors.cpu().numpy())

    threshold = np.percentile(all_errors, percentile)
    return threshold


# ============================================================================
# DATA LOADING
# ============================================================================

def load_data_from_json(file_path: str) -> np.ndarray:
    """Load Summary Vectors từ JSON file.

    Supports 2 formats:
    1. App export format: {"version": "1.0", "data": [{"features": [...]}]}
    2. Simple format: [{"features": [...]}]
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    vectors = []

    # Check if it's the new app export format
    if isinstance(data, dict) and 'data' in data:
        print(f"Detected app export format (v{data.get('version', '?')})")
        print(f"Exported at: {data.get('exported_at', 'unknown')}")
        print(f"Total samples in export: {data.get('total_samples', '?')}")
        items = data['data']
    else:
        # Old simple format: direct array
        items = data if isinstance(data, list) else []

    for item in items:
        if 'features' in item:
            features = item['features']
            if len(features) >= FEATURE_COUNT:
                vectors.append(features[:FEATURE_COUNT])

    if len(vectors) == 0:
        print(f"Warning: No valid vectors found in {file_path}")
    else:
        print(f"Loaded {len(vectors)} vectors from {file_path}")

    return np.array(vectors, dtype=np.float32)


def generate_synthetic_data(num_samples: int = 1000,
                           sequence_length: int = DEFAULT_SEQUENCE_LENGTH) -> np.ndarray:
    """Generate synthetic data cho testing."""
    print(f"Generating {num_samples} synthetic samples...")

    # Normal behavior patterns
    base_pattern = np.random.randn(num_samples, FEATURE_COUNT) * 0.3

    # Add temporal patterns (trends, seasonality)
    time_effect = np.sin(np.arange(num_samples) / 50)[:, np.newaxis] * 0.2
    base_pattern += time_effect

    # Add some noise
    noise = np.random.randn(num_samples, FEATURE_COUNT) * 0.1
    data = base_pattern + noise

    # Normalize to [0, 1]
    data = (data - data.min(axis=0)) / (data.max(axis=0) - data.min(axis=0) + 1e-8)

    return data.astype(np.float32)


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Train LSTM/GRU AutoEncoder for Anomaly Detection')

    parser.add_argument('--data', type=str, help='Path to training data (JSON)')
    parser.add_argument('--output', type=str, default='model.pth', help='Output model path')
    parser.add_argument('--model-type', type=str, default='lstm', choices=['lstm', 'gru'],
                        help='Model type: lstm or gru')
    parser.add_argument('--sequence-length', type=int, default=DEFAULT_SEQUENCE_LENGTH,
                        help=f'Sequence length L (default: {DEFAULT_SEQUENCE_LENGTH})')
    parser.add_argument('--hidden-dim', type=int, default=DEFAULT_HIDDEN_DIM,
                        help=f'LSTM hidden dimension (default: {DEFAULT_HIDDEN_DIM})')
    parser.add_argument('--latent-dim', type=int, default=DEFAULT_LATENT_DIM,
                        help=f'Latent dimension (default: {DEFAULT_LATENT_DIM})')
    parser.add_argument('--num-layers', type=int, default=DEFAULT_NUM_LAYERS,
                        help=f'Number of LSTM layers (default: {DEFAULT_NUM_LAYERS})')
    parser.add_argument('--epochs', type=int, default=DEFAULT_EPOCHS,
                        help=f'Training epochs (default: {DEFAULT_EPOCHS})')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE,
                        help=f'Batch size (default: {DEFAULT_BATCH_SIZE})')
    parser.add_argument('--lr', type=float, default=DEFAULT_LEARNING_RATE,
                        help=f'Learning rate (default: {DEFAULT_LEARNING_RATE})')
    parser.add_argument('--synthetic', type=int, default=0,
                        help='Generate synthetic data with N samples')
    parser.add_argument('--device', type=str, default='auto',
                        help='Device: cpu, cuda, or auto')

    args = parser.parse_args()

    # Device selection
    if args.device == 'auto':
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    else:
        device = args.device

    print(f"\n{'='*60}")
    print("AI Security App - LSTM/GRU AutoEncoder Training")
    print(f"{'='*60}")
    print(f"Model Type: {args.model_type.upper()}")
    print(f"Sequence Length: {args.sequence_length}")
    print(f"Features: {FEATURE_COUNT}")
    print(f"Device: {device}")

    # Load or generate data
    if args.synthetic > 0:
        raw_data = generate_synthetic_data(args.synthetic)
    elif args.data:
        if not os.path.exists(args.data):
            print(f"Error: Data file not found: {args.data}")
            sys.exit(1)
        raw_data = load_data_from_json(args.data)
        print(f"Loaded {len(raw_data)} samples from {args.data}")
    else:
        print("No data specified. Generating 1000 synthetic samples...")
        raw_data = generate_synthetic_data(1000)

    if len(raw_data) < args.sequence_length + 1:
        print(f"Error: Need at least {args.sequence_length + 1} samples")
        sys.exit(1)

    # Normalize
    normalized_data, min_vals, max_vals = normalize_features(raw_data)

    # Create sequences
    sequences = create_sequences(normalized_data, args.sequence_length)
    print(f"Created {len(sequences)} sequences of length {args.sequence_length}")

    # Split train/val (80/20)
    split_idx = int(len(sequences) * 0.8)
    train_sequences = sequences[:split_idx]
    val_sequences = sequences[split_idx:]

    print(f"Train: {len(train_sequences)}, Validation: {len(val_sequences)}")

    # Create DataLoaders
    train_dataset = SequenceDataset(train_sequences)
    val_dataset = SequenceDataset(val_sequences)

    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size)

    # Create model
    ModelClass = LSTMAutoEncoder if args.model_type == 'lstm' else GRUAutoEncoder
    model = ModelClass(
        input_dim=FEATURE_COUNT,
        hidden_dim=args.hidden_dim,
        latent_dim=args.latent_dim,
        num_layers=args.num_layers,
        sequence_length=args.sequence_length,
    )

    print(f"\nModel Architecture:")
    print(f"  Input: ({args.sequence_length}, {FEATURE_COUNT})")
    print(f"  Hidden: {args.hidden_dim}")
    print(f"  Latent: {args.latent_dim}")
    print(f"  Layers: {args.num_layers}")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")

    # Train
    history = train_model(
        model, train_loader, val_loader,
        epochs=args.epochs,
        learning_rate=args.lr,
        device=device
    )

    # Calculate threshold
    model = model.to(device)
    threshold = calculate_threshold(model, train_loader, percentile=95, device=device)
    print(f"Anomaly Threshold (95th percentile): {threshold:.6f}")

    # Save model
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    save_dict = {
        'model_state_dict': model.cpu().state_dict(),
        'model_type': args.model_type,
        'config': {
            'input_dim': FEATURE_COUNT,
            'hidden_dim': args.hidden_dim,
            'latent_dim': args.latent_dim,
            'num_layers': args.num_layers,
            'sequence_length': args.sequence_length,
        },
        'normalization': {
            'min_vals': min_vals.tolist(),
            'max_vals': max_vals.tolist(),
        },
        'threshold': threshold,
        'history': history,
        'trained_at': datetime.now().isoformat(),
    }

    torch.save(save_dict, output_path)
    print(f"\nModel saved to: {output_path}")
    print(f"File size: {output_path.stat().st_size / 1024:.1f} KB")

    # Output summary as JSON (for Rust to parse)
    summary = {
        'success': True,
        'model_path': str(output_path),
        'model_type': args.model_type,
        'sequence_length': args.sequence_length,
        'features': FEATURE_COUNT,
        'threshold': float(threshold),
        'best_loss': float(history['best_loss']),
        'epochs': args.epochs,
    }
    print(f"\n[RESULT]{json.dumps(summary)}")


if __name__ == '__main__':
    main()
