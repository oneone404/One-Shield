import argparse
import json
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def load_data(file_path):
    print(f"Loading dataset from {file_path}...")
    data = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    record = json.loads(line)
                    features = record.get('features')
                    threat = record.get('threat')
                    user_label = record.get('user_label')

                    if not features or len(features) != 15:
                        continue

                    # Label Logic:
                    # 1. User Override takes precedence
                    # 2. "Malicious" is class 1 (Positive)
                    # 3. Everything else (Benign, Suspicious) is class 0 (Negative)
                    # Note: We treat Suspicious as Benign for training to ensure high precision for alerts

                    label = 0
                    effective_label = user_label if user_label else threat

                    if isinstance(effective_label, str):
                        effective_label = effective_label.lower()
                        if "malicious" in effective_label:
                            label = 1

                    row = features + [label]
                    data.append(row)
                except json.JSONDecodeError:
                    continue

        print(f"Loaded {len(data)} valid records.")
        if len(data) > 0:
            columns = [f"f{i}" for i in range(15)] + ["target"]
            return pd.DataFrame(data, columns=columns)
        return pd.DataFrame()

    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        sys.exit(1)

def train(df, feature_count):
    if df.empty:
        print("DataFrame is empty.")
        return None

    X = df.iloc[:, :feature_count].values.astype(np.float32)
    y = df.iloc[:, feature_count].values.astype(np.int32)

    # Logic if not enough data for split
    if len(df) < 10:
        print("Warning: Dataset too small for validation split. Training on full set.")
        X_train, y_train = X, y
        X_test, y_test = X, y
    else:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"Training RandomForest on {len(X_train)} samples...")
    # RandomForest: Good balance of bias/variance, handles non-linearities, explainable
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    print("\n--- Evaluation ---")
    y_pred = clf.predict(X_test)
    try:
        print(confusion_matrix(y_test, y_pred))
        print(classification_report(y_test, y_pred))
    except Exception as e:
        print(f"Evaluation error: {e}")

    return clf

def export_onnx(model, output_path, feature_count):
    print(f"Exporting to ONNX: {output_path}")

    # Define input type: [None, feature_count] float32
    initial_type = [('float_input', FloatTensorType([None, feature_count]))]

    # Convert using skl2onnx
    # target_opset=12 is widely supported
    onx = convert_sklearn(model, initial_types=initial_type, target_opset=12)

    # Write to disk
    with open(output_path, "wb") as f:
        f.write(onx.SerializeToString())

    print(f"✅ Model saved successfully at {output_path}")

def save_metadata(output_path, feature_count, records):
    # Sidecar JSON: model.onnx -> model.meta
    meta_path = os.path.splitext(output_path)[0] + ".meta"

    # Simple versioning based on timestamp if not provided
    version = f"v{pd.Timestamp.now().strftime('%Y.%m.%d')}"

    data = {
        "version": version,
        "records": int(records),
        "features": feature_count,
        "created_at": int(pd.Timestamp.now().timestamp()),
        "engine": "onnx-randomforest"
    }

    try:
        with open(meta_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"✅ Metadata saved to {meta_path}")
    except Exception as e:
        print(f"Warning: Failed to save metadata: {e}")

def main():
    parser = argparse.ArgumentParser(description="Train AI Security Model (RandomForest -> ONNX)")
    parser.add_argument("--input", required=True, help="Path to input dataset (.jsonl)")
    parser.add_argument("--out", required=True, help="Path to output model (.onnx)")
    parser.add_argument("--features", type=int, default=15, help="Number of features (default: 15)")

    args = parser.parse_args()

    # 1. Load Data
    df = load_data(args.input)
    if df.empty:
        print("Dataset empty or invalid. Exiting.")
        sys.exit(1)

    # 2. Train Model
    model = train(df, args.features)
    if model is None:
        sys.exit(1)

    # 3. Export ONNX
    export_onnx(model, args.out, args.features)

    # 4. Save Metadata
    save_metadata(args.out, args.features, len(df))

if __name__ == "__main__":
    main()
