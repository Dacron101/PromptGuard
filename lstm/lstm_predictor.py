"""
lstm/lstm_predictor.py
Rudimentary LSTM for predicting daily variable spending behaviour.

Architecture: single LSTM layer (32 units) -> Dense(16) -> Dense(1)
Designed for fast training (<5s on CPU) using a synthetic dataset that
mirrors the spending patterns seeded in seedDb.js.

Usage:
    python lstm_predictor.py
    python lstm_predictor.py --days 14 --epochs 80 --window 7

Outputs:
  - Training loss curve (ASCII)
  - Forecasted daily spend for the next N days
  - Risk flag if projected spend pushes the user into overdraft
"""

import argparse
import random
import math
import json

import numpy as np

# ---------------------------------------------------------------------------
# Optional: nicer output if matplotlib is available, otherwise ASCII only
# ---------------------------------------------------------------------------
try:
    import matplotlib
    matplotlib.use("Agg")          # headless
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


# ===========================================================================
# 1. SYNTHETIC DATA GENERATION
#    Mirrors the spending profile of user_123 from seedDb.js:
#      - $6–7/day coffee
#      - ~$30/day groceries (weekly spike ~$90 once a week)
#      - ~$10–35 delivery/dining 2–3×/week
#      - random misc ($5–55) every few days
# ===========================================================================

def generate_daily_spend(n_days: int = 120, seed: int = 42) -> np.ndarray:
    """Generate n_days of realistic synthetic daily variable spend."""
    rng = random.Random(seed)
    spend = []

    for day in range(n_days):
        daily = 0.0

        # Coffee (daily, small variance)
        daily += rng.uniform(5.5, 7.5)

        # Groceries: big shop once/week, small top-up mid-week
        if day % 7 == 0:
            daily += rng.uniform(75.0, 100.0)
        elif day % 7 == 3:
            daily += rng.uniform(20.0, 45.0)

        # Dining / delivery ~3× per week
        if rng.random() < 0.43:
            daily += rng.uniform(18.0, 58.0)

        # Misc (Amazon, Target, etc.) ~every 4–5 days
        if rng.random() < 0.22:
            daily += rng.uniform(15.0, 55.0)

        spend.append(round(daily, 2))

    return np.array(spend, dtype=np.float32)


# ===========================================================================
# 2. SEQUENCE BUILDER
#    Turns the 1-D daily spend series into (X, y) supervised pairs.
#    X shape: (samples, window, 1)   y shape: (samples,)
# ===========================================================================

def make_sequences(series: np.ndarray, window: int):
    X, y = [], []
    for i in range(len(series) - window):
        X.append(series[i : i + window])
        y.append(series[i + window])
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32)


# ===========================================================================
# 3. LSTM MODEL
# ===========================================================================

class SpendLSTM(nn.Module):
    """
    Single-layer LSTM -> two dense layers.
    Tiny by design: trains in seconds on a CPU.
    """
    def __init__(self, hidden_size: int = 32):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=1,
            hidden_size=hidden_size,
            num_layers=1,
            batch_first=True,
        )
        self.head = nn.Sequential(
            nn.Linear(hidden_size, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
        )

    def forward(self, x):
        # x: (batch, seq_len, 1)
        out, _ = self.lstm(x)
        last = out[:, -1, :]    # take final hidden state
        return self.head(last).squeeze(-1)


# ===========================================================================
# 4. TRAINING
# ===========================================================================

def train(model, loader, epochs: int, lr: float = 1e-3):
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()
    history = []

    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        for xb, yb in loader:
            optimizer.zero_grad()
            pred = model(xb)
            loss = criterion(pred, yb)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        avg = epoch_loss / len(loader)
        history.append(avg)

        if epoch % max(1, epochs // 10) == 0 or epoch == 1:
            print(f"  Epoch {epoch:>4}/{epochs}  loss={avg:.4f}")

    return history


# ===========================================================================
# 5. ROLLING FORECAST
#    Iteratively predicts one step ahead, appends prediction to window,
#    and repeats for forecast_days steps.
# ===========================================================================

def forecast(model, seed_window: np.ndarray, scaler_max: float,
             forecast_days: int) -> list[float]:
    model.eval()
    window = list(seed_window / scaler_max)   # normalise
    predictions = []

    with torch.no_grad():
        for _ in range(forecast_days):
            x = torch.tensor(window[-len(seed_window):],
                             dtype=torch.float32).unsqueeze(0).unsqueeze(-1)
            pred_norm = model(x).item()
            pred_norm = max(0.0, pred_norm)   # spending can't be negative
            predictions.append(round(pred_norm * scaler_max, 2))
            window.append(pred_norm)

    return predictions


# ===========================================================================
# 6. OUTPUT HELPERS
# ===========================================================================

def ascii_bar(value: float, max_val: float, width: int = 30) -> str:
    filled = int((value / max_val) * width) if max_val > 0 else 0
    return "█" * filled + "░" * (width - filled)


def print_forecast_table(predictions: list[float], current_balance: float,
                         days_until_payday: int):
    print("\n" + "=" * 60)
    print("  📈  LSTM SPEND FORECAST  (next {} days)".format(len(predictions)))
    print("=" * 60)

    max_pred = max(predictions) if predictions else 1.0
    running_balance = current_balance
    threshold = 0.0

    print(f"  {'Day':<5} {'Predicted Spend':>16}  {'Bar':<32}  {'Running Balance':>16}")
    print("  " + "-" * 72)

    for i, p in enumerate(predictions, 1):
        running_balance -= p
        bar = ascii_bar(p, max_pred)
        marker = ""
        if i <= days_until_payday and running_balance < threshold:
            marker = "  ⚠️  OVERDRAFT"
        print(f"  Day {i:<3}  ${p:>13.2f}  {bar}  ${running_balance:>14.2f}{marker}")

    total = sum(predictions)
    final_balance = current_balance - total
    print("  " + "-" * 72)
    print(f"  {'TOTAL':<5}  ${total:>13.2f}")
    print(f"\n  Forecasted balance after {len(predictions)} days: ${final_balance:.2f}")
    if final_balance < 0:
        print(f"  ⛔  DEFICIT OF ${abs(final_balance):.2f} — HIGH OVERDRAFT RISK")
    else:
        print(f"  ✅  Balance remains positive through forecast window")
    print("=" * 60)


def save_chart(history: list[float], predictions: list[float],
               train_series: np.ndarray, output_path: str = "forecast.png"):
    if not HAS_MPL:
        return
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
    fig.patch.set_facecolor("#0a0d14")
    for ax in (ax1, ax2):
        ax.set_facecolor("#111827")
        ax.tick_params(colors="#64748b")
        for spine in ax.spines.values():
            spine.set_edgecolor("#1f2d45")

    # Training loss
    ax1.plot(history, color="#3b82f6", linewidth=1.5)
    ax1.set_title("Training Loss (MSE)", color="#e2e8f0")
    ax1.set_xlabel("Epoch", color="#64748b")
    ax1.set_ylabel("Loss", color="#64748b")

    # Historical + forecast
    hist_days = list(range(len(train_series)))
    fore_days = list(range(len(train_series), len(train_series) + len(predictions)))
    ax2.plot(hist_days[-30:], train_series[-30:],
             color="#64748b", linewidth=1, label="Historical (last 30d)")
    ax2.plot(fore_days, predictions,
             color="#f59e0b", linewidth=2, linestyle="--", label="LSTM Forecast")
    ax2.axvline(x=len(train_series) - 1, color="#ef4444",
                linewidth=1, linestyle=":")
    ax2.set_title("Daily Spend Forecast", color="#e2e8f0")
    ax2.set_xlabel("Day", color="#64748b")
    ax2.set_ylabel("$ Spend", color="#64748b")
    ax2.legend(facecolor="#111827", labelcolor="#e2e8f0", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    print(f"\n  Chart saved → {output_path}")


# ===========================================================================
# 7. MAIN
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="LSTM Spend Forecaster")
    parser.add_argument("--days",    type=int, default=12,
                        help="Days to forecast (default: 12, i.e. until payday)")
    parser.add_argument("--epochs",  type=int, default=60,
                        help="Training epochs (default: 60)")
    parser.add_argument("--window",  type=int, default=7,
                        help="Look-back window in days (default: 7)")
    parser.add_argument("--balance", type=float, default=850.0,
                        help="Current account balance (default: 850)")
    parser.add_argument("--payday",  type=int, default=12,
                        help="Days until next payday (default: 12)")
    parser.add_argument("--chart",   action="store_true",
                        help="Save forecast chart as forecast.png")
    parser.add_argument("--json",    action="store_true",
                        help="Also print machine-readable JSON summary")
    args = parser.parse_args()

    print("\n🧠 LSTM Spending Behaviour Model")
    print("   Architecture : LSTM(32) → Dense(16) → Dense(1)")
    print(f"   Window       : {args.window} days")
    print(f"   Epochs       : {args.epochs}")
    print(f"   Forecast     : {args.days} days ahead\n")

    # --- 1. Data ---
    print("⚙️  Generating synthetic spend history (120 days)...")
    series = generate_daily_spend(n_days=120)

    # Normalise by max value so the LSTM sees [0, 1] range
    scaler_max = float(series.max())
    series_norm = series / scaler_max

    X, y = make_sequences(series_norm, window=args.window)
    X_t = torch.tensor(X).unsqueeze(-1)   # (N, window, 1)
    y_t = torch.tensor(y)

    dataset = TensorDataset(X_t, y_t)
    loader  = DataLoader(dataset, batch_size=16, shuffle=True)

    # --- 2. Model ---
    model = SpendLSTM(hidden_size=32)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"   Model params : {total_params:,}\n")

    # --- 3. Train ---
    print("🏋️  Training...")
    history = train(model, loader, epochs=args.epochs)

    # --- 4. Forecast ---
    seed_window = series[-args.window:]       # last N days of known history
    predictions = forecast(model, seed_window, scaler_max, args.days)

    # --- 5. Print results ---
    print_forecast_table(predictions, args.balance, args.payday)

    # --- 6. Optional chart ---
    if args.chart:
        save_chart(history, predictions, series)
    elif HAS_MPL:
        print("\n  Tip: run with --chart to save a forecast.png")

    # --- 7. Optional JSON for piping into the Node.js pipeline ---
    if args.json:
        summary = {
            "model": "LSTM(32)",
            "window_days": args.window,
            "forecast_days": args.days,
            "predicted_daily_spend": predictions,
            "total_predicted_spend": round(sum(predictions), 2),
            "forecasted_balance": round(args.balance - sum(predictions), 2),
            "is_at_risk": (args.balance - sum(predictions)) < 0,
        }
        print("\n--- JSON OUTPUT ---")
        print(json.dumps(summary, indent=2))

    print()


if __name__ == "__main__":
    main()
