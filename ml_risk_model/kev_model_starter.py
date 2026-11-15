"""
KEV prediction - starter script (practice data)
================================================

Question the model answers:
    "Will this CVE be added to CISA KEV within the observation window?"

This script uses MADE-UP practice data so you can see every step work
before touching real Neo data. Later, you replace make_practice_data()
with a loader for your real backtest data. Everything else stays the same.

Run:   pip install torch
       python kev_model_starter.py
"""

import torch
import torch.nn as nn

torch.manual_seed(42)  # same random numbers every run, so results repeat


# ---------------------------------------------------------------------------
# STEP 1 - The data
# Each row is one CVE. Each column is one fact about it (a "feature").
# The label is 1 if it later entered KEV, 0 if not.
# ---------------------------------------------------------------------------
FEATURES = [
    "cvss_base",          # 0-10 severity score
    "av_network",         # 1 = attackable over the network
    "complexity_low",     # 1 = easy to exploit
    "privileges_none",    # 1 = attacker needs no account
    "no_user_action",     # 1 = victim does not need to click anything
    "epss",               # 0-1 exploitation probability from FIRST
    "public_exploit",     # 1 = exploit code is publicly available
    "popular_vendor",     # 1 = widely deployed product
]


def make_practice_data(n=20000):
    """Invent realistic-looking CVEs. Replace this with your real data later."""
    quarter = torch.randint(0, 20, (n,))                 # 20 quarters = 5 years
    cvss = (torch.randn(n) * 1.8 + 6.5).clamp(0, 10)
    av_network = (torch.rand(n) < 0.7).float()
    complexity_low = (torch.rand(n) < 0.6).float()
    privileges_none = (torch.rand(n) < 0.5).float()
    no_user_action = (torch.rand(n) < 0.6).float()
    epss = torch.rand(n) ** 6                            # most EPSS scores are tiny
    public_exploit = (torch.rand(n) < 0.1).float()
    popular_vendor = (torch.rand(n) < 0.2).float()

    X = torch.stack([cvss / 10, av_network, complexity_low, privileges_none,
                     no_user_action, epss, public_exploit, popular_vendor], dim=1)

    # Hidden "truth" used only to invent labels. The model never sees this.
    # Note: popular_vendor and public_exploit matter a lot here - things a
    # simple CVSS+EPSS formula ignores. That is the gap a learned model can find.
    # The below two lines are made up to generate some real world values
    risk = (-9.0 + 1.5 * cvss / 10 + 0.8 * av_network + 0.6 * privileges_none
            + 4.0 * epss + 2.5 * public_exploit + 2.0 * popular_vendor)
    y = (torch.rand(n) < torch.sigmoid(risk)).float()
    return X, y, quarter


X, y, quarter = make_practice_data()
print(f"CVEs: {len(y):,}   in KEV: {int(y.sum())}   base rate: {y.mean():.2%}")


# ---------------------------------------------------------------------------
# STEP 2 - Split by TIME, never randomly
# Train on older quarters, test on the newest ones.
# Like studying past exam papers, then sitting this year's exam.
# ---------------------------------------------------------------------------
train = quarter < 16          # quarters 0-15 -> learn
test = quarter >= 16          # quarters 16-19 -> grade (the "future")
X_train, y_train = X[train], y[train]
X_test, y_test = X[test], y[test]
print(f"Train: {len(y_train):,} CVEs ({int(y_train.sum())} KEV)   "
      f"Test: {len(y_test):,} CVEs ({int(y_test.sum())} KEV)\n")


# ---------------------------------------------------------------------------
# STEP 3 - The models
# ---------------------------------------------------------------------------
# (a) Logistic regression = the simplest learned model.
#     One weight per feature. The sanity-check baseline.
logistic = nn.Linear(len(FEATURES), 1)

# (b) Small neural network. Can learn combinations, e.g.
#     "network-reachable AND no privileges needed" together.
neural_net = nn.Sequential(
    nn.Linear(len(FEATURES), 16),
    nn.ReLU(),
    nn.Linear(16, 1),
)


def train_model(model, X, y, epochs=300):
    # Rarity fix: missing a real KEV CVE costs as much as all the
    # false alarms combined. Without this, the model just says "no" to everything.
    pos_weight = (y == 0).sum() / (y == 1).sum()
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

    for epoch in range(epochs):
        optimizer.zero_grad()                 # clear last round's corrections
        scores = model(X).squeeze(1)          # 1. make predictions
        loss = loss_fn(scores, y)             # 2. measure how wrong they are
        loss.backward()                       # 3. work out which weights to nudge
        optimizer.step()                      # 4. nudge them
        if epoch % 100 == 0:
            print(f"    round {epoch:3d}   error {loss.item():.3f}")
    return model


print("Training logistic regression...")
train_model(logistic, X_train, y_train)
print("Training neural network...")
train_model(neural_net, X_train, y_train)


# ---------------------------------------------------------------------------
# STEP 4 - The hand-made rule (stand-in for Neo's composite score)
# Replace these weights with Neo's real formula.
# ---------------------------------------------------------------------------
def hand_formula(X):
    cvss, epss = X[:, 0], X[:, 5]
    return  cvss * epss/10


# ---------------------------------------------------------------------------
# STEP 5 - Grade everyone the same way: lift@k
# "Of the top k CVEs on your list, how many really entered KEV,
#  versus how many random picking would find?"
# ---------------------------------------------------------------------------
def lift_at_k(scores, y, k):
    top_k = torch.argsort(scores, descending=True)[:k]
    hits = y[top_k].sum().item()
    random_expect = k * y.mean().item()
    return hits, random_expect, hits / random_expect if random_expect else 0


with torch.no_grad():                          # grading only, no learning
    contenders = {
        "Hand formula": hand_formula(X_test),
        "Logistic reg": logistic(X_test).squeeze(1),
        "Neural net": neural_net(X_test).squeeze(1),
    }

print("\nRESULTS on unseen future quarters")
print(f"{'':14}" + "".join(f"{'top ' + str(k):>18}" for k in (10, 25, 50, 100)))
for name, scores in contenders.items():
    row = f"{name:14}"
    for k in (10, 25, 50, 100):
        hits, rand, lift = lift_at_k(scores, y_test, k)
        row += f"{int(hits):>5} hits ({lift:4.1f}x)"
    print(row)
print("\n'hits' = real KEV CVEs in the top k.  'x' = times better than random.")


# ---------------------------------------------------------------------------
# STEP 6 - Save the model so Neo could load it later (Auditable pillar)
# ---------------------------------------------------------------------------
torch.save({"model": neural_net.state_dict(), "features": FEATURES,
            "version": "kev-practice-v0.1"}, "kev_model_v0.1.pt")
print("\nSaved model as kev_model_v0.1.pt (version kev-practice-v0.1)")