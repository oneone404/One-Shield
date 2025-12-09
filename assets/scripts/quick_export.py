#!/usr/bin/env python3
"""
Quick ONNX Export - Compatible with train.py model architecture
"""

import torch
import torch.nn as nn
import json
import sys
import os

# ============================================================================
# Model definitions - EXACTLY matching train.py
# ============================================================================

class LSTMEncoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, latent_dim, num_layers):
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
        last_hidden = hidden[-1]
        latent = self.fc_latent(last_hidden)
        return latent, (hidden, cell)


class LSTMDecoder(nn.Module):
    def __init__(self, latent_dim, hidden_dim, output_dim, num_layers, sequence_length):
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

    def forward(self, latent, sequence_length=None):
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
    def __init__(self, input_dim, hidden_dim, latent_dim, num_layers, sequence_length):
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


def main():
    model_path = sys.argv[1] if len(sys.argv) > 1 else '../core-service/models/model.pth'
    output_path = sys.argv[2] if len(sys.argv) > 2 else '../core-service/models/model.onnx'

    print(f"Loading model from: {model_path}")

    # Load checkpoint
    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
    config = checkpoint['config']

    print(f"Config: {config}")

    # Create model
    model = LSTMAutoEncoder(
        input_dim=config['input_dim'],
        hidden_dim=config['hidden_dim'],
        latent_dim=config['latent_dim'],
        num_layers=config['num_layers'],
        sequence_length=config['sequence_length']
    )

    # Load weights
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()

    print("Model loaded successfully!")

    # Dummy input
    dummy = torch.randn(1, config['sequence_length'], config['input_dim'])

    print(f"Exporting to ONNX: {output_path}")
    print(f"Input shape: {dummy.shape}")

    # Export with legacy API (disable dynamo for compatibility)
    with torch.no_grad():
        torch.onnx.export(
            model,
            dummy,
            output_path,
            export_params=True,
            opset_version=14,
            do_constant_folding=True,
            input_names=['input_sequence'],
            output_names=['reconstructed_sequence'],
            dynamic_axes={
                'input_sequence': {0: 'batch_size'},
                'reconstructed_sequence': {0: 'batch_size'}
            },
            dynamo=False
        )

    print(f"ONNX model saved: {output_path}")

    # Save metadata
    norm = checkpoint.get('normalization', {})
    min_vals = norm.get('min_vals', [0.0] * 15)
    max_vals = norm.get('max_vals', [1.0] * 15)

    # Handle numpy arrays
    if hasattr(min_vals, 'tolist'):
        min_vals = min_vals.tolist()
    if hasattr(max_vals, 'tolist'):
        max_vals = max_vals.tolist()

    metadata = {
        'model_type': checkpoint.get('model_type', 'lstm'),
        'config': config,
        'threshold': float(checkpoint.get('threshold', 0.027)),
        'normalization': {
            'min_vals': min_vals,
            'max_vals': max_vals
        }
    }

    metadata_path = output_path + '.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"Metadata saved: {metadata_path}")

    # Verify file sizes
    onnx_size = os.path.getsize(output_path)
    print(f"\nONNX file size: {onnx_size / 1024:.1f} KB")

    # Verify with ONNX Runtime
    try:
        import onnxruntime as ort
        session = ort.InferenceSession(output_path)

        # Test inference
        test_input = dummy.numpy()
        result = session.run(None, {'input_sequence': test_input})
        print(f"Verification: Output shape = {result[0].shape}")
        print("ONNX Runtime verification: PASSED")
    except Exception as e:
        print(f"Note: ONNX Runtime verification skipped ({e})")

    print("\n" + "="*50)
    print("Export completed successfully!")
    print("="*50)

if __name__ == "__main__":
    main()
