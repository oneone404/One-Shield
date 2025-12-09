#!/usr/bin/env python3
"""
AI Security App - Export Model to ONNX
=======================================

Chuyển đổi mô hình LSTM/GRU PyTorch sang định dạng ONNX
để load trực tiếp trong Rust ONNX Runtime.

Usage:
    python export_model.py --model model.pth --output model.onnx
    python export_model.py --model model.pth --format torchscript
"""

import argparse
import json
import sys
import os
from pathlib import Path

try:
    import torch
    import torch.nn as nn
    import torch.onnx
except ImportError:
    print("PyTorch chưa được cài đặt. Chạy: pip install torch")
    sys.exit(1)


# ============================================================================
# CONSTANTS (match với train.py)
# ============================================================================

FEATURE_COUNT = 15
DEFAULT_SEQUENCE_LENGTH = 5


# ============================================================================
# MODEL DEFINITIONS (copy từ train.py)
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
            dropout=0.0,  # No dropout for export
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
            dropout=0.0,
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
            dropout=0.0,
        )
        self.fc_latent = nn.Linear(hidden_dim, latent_dim)

        self.fc_hidden = nn.Linear(latent_dim, hidden_dim * num_layers)
        self.decoder_gru = nn.GRU(
            input_size=latent_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.0,
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


# ============================================================================
# ONNX EXPORT
# ============================================================================

def export_to_onnx(model: nn.Module, output_path: str, config: dict,
                   opset_version: int = 14) -> dict:
    """
    Export PyTorch model to ONNX format.
    """
    model.eval()

    # Create dummy input với shape chính xác
    sequence_length = config.get('sequence_length', DEFAULT_SEQUENCE_LENGTH)
    input_dim = config.get('input_dim', FEATURE_COUNT)

    dummy_input = torch.randn(1, sequence_length, input_dim)

    print(f"\nDummy input shape: {dummy_input.shape}")
    print(f"  - Batch size: 1")
    print(f"  - Sequence length: {sequence_length}")
    print(f"  - Features: {input_dim}")

    # Define input/output names
    input_names = ["input_sequence"]
    output_names = ["reconstructed_sequence"]

    # Dynamic axes cho batch size flexibility
    dynamic_axes = {
        "input_sequence": {0: "batch_size"},
        "reconstructed_sequence": {0: "batch_size"},
    }

    print(f"\nExporting to ONNX (opset {opset_version})...")

    # Export
    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        export_params=True,
        opset_version=opset_version,
        do_constant_folding=True,
        input_names=input_names,
        output_names=output_names,
        dynamic_axes=dynamic_axes,
    )

    # Verify export
    file_size = os.path.getsize(output_path)

    print(f"✅ ONNX export successful!")
    print(f"   Output: {output_path}")
    print(f"   Size: {file_size / 1024:.1f} KB")

    # Optional: Verify với ONNX Runtime
    try:
        import onnxruntime as ort

        session = ort.InferenceSession(output_path)

        # Run inference test
        input_name = session.get_inputs()[0].name
        output = session.run(None, {input_name: dummy_input.numpy()})

        print(f"\n✅ ONNX Runtime verification passed!")
        print(f"   Input: {input_name} -> {dummy_input.shape}")
        print(f"   Output: {output[0].shape}")

    except ImportError:
        print("\n⚠️  onnxruntime not installed, skipping verification")
        print("   Install with: pip install onnxruntime")

    return {
        'success': True,
        'output_path': output_path,
        'file_size': file_size,
        'input_shape': list(dummy_input.shape),
        'opset_version': opset_version,
    }


def export_to_torchscript(model: nn.Module, output_path: str, config: dict) -> dict:
    """
    Export PyTorch model to TorchScript format.
    """
    model.eval()

    sequence_length = config.get('sequence_length', DEFAULT_SEQUENCE_LENGTH)
    input_dim = config.get('input_dim', FEATURE_COUNT)

    dummy_input = torch.randn(1, sequence_length, input_dim)

    print(f"\nExporting to TorchScript...")

    # Trace the model
    traced_model = torch.jit.trace(model, dummy_input)

    # Save
    traced_model.save(output_path)

    file_size = os.path.getsize(output_path)

    print(f"✅ TorchScript export successful!")
    print(f"   Output: {output_path}")
    print(f"   Size: {file_size / 1024:.1f} KB")

    return {
        'success': True,
        'output_path': output_path,
        'file_size': file_size,
        'format': 'torchscript',
    }


# ============================================================================
# MODEL LOADING
# ============================================================================

def load_model(model_path: str):
    """Load PyTorch model từ checkpoint."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)

    model_type = checkpoint.get('model_type', 'lstm')
    config = checkpoint.get('config', {})

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

    return model, config, checkpoint


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Export PyTorch model to ONNX/TorchScript')

    parser.add_argument('--model', type=str, required=True, help='Input PyTorch model (.pth)')
    parser.add_argument('--output', type=str, help='Output path (default: same name with new extension)')
    parser.add_argument('--format', type=str, default='onnx', choices=['onnx', 'torchscript'],
                        help='Export format (default: onnx)')
    parser.add_argument('--opset', type=int, default=14, help='ONNX opset version (default: 14)')

    args = parser.parse_args()

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        base = os.path.splitext(args.model)[0]
        ext = '.onnx' if args.format == 'onnx' else '.pt'
        output_path = base + ext

    print(f"\n{'='*60}")
    print("AI Security App - Model Export")
    print(f"{'='*60}")
    print(f"Input:  {args.model}")
    print(f"Output: {output_path}")
    print(f"Format: {args.format.upper()}")

    # Load model
    print(f"\nLoading model...")
    model, config, checkpoint = load_model(args.model)

    print(f"Model type: {checkpoint.get('model_type', 'unknown').upper()}")
    print(f"Config: {json.dumps(config, indent=2)}")

    # Export
    if args.format == 'onnx':
        result = export_to_onnx(model, output_path, config, args.opset)
    else:
        result = export_to_torchscript(model, output_path, config)

    # Save metadata
    metadata_path = output_path + '.json'
    metadata = {
        'source_model': args.model,
        'format': args.format,
        'config': config,
        'threshold': checkpoint.get('threshold', 0.7),
        'normalization': checkpoint.get('normalization', {}),
        **result,
    }

    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"\n✅ Metadata saved to: {metadata_path}")

    # Final summary
    print(f"\n{'='*60}")
    print("Export Complete!")
    print(f"{'='*60}")
    print(f"\nFiles created:")
    print(f"  - {output_path}")
    print(f"  - {metadata_path}")

    print(f"\n[RESULT]{json.dumps({'success': True, 'output': output_path})}")


if __name__ == '__main__':
    main()
