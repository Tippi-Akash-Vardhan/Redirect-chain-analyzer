#  Redirect-chain-analyzer

Automatically classifies domains flagged in a SecurityScorecard report as:
-  **True Positive** — confirmed owned by the organization
-  **False Positive** — no ownership evidence found
-  **Needs Manual Review** — inconclusive results

---

##  How It Works

1. **Master List Check** — Checks if the domain or its resolved IP exists in your known domain/IP lists
2. **Technical Checks** — Runs WHOIS lookup, redirect tracing, and NS resolution
3. **Keyword Detection** — Searches for ownership keywords (e.g., `gannett`, `usatoday`, `newsquest`)
4. **Parallel Processing** — Uses ThreadPoolExecutor for fast, concurrent domain analysis

---

##  Input Files Required

| File | Description |
|------|-------------|
| `security_scorecard.csv` | Exported CSV from SecurityScorecard with a `domain` column |
| `Gannett_Domains.xlsx` | Master list of known owned domains |
| `gannett_ips.xlsx` | Master list of known owned IP addresses |

---

##  Output Files

| File | Description |
|------|-------------|
| `true_positive.csv` | Domains confirmed as owned |
| `false_positive.csv` | Domains with no ownership evidence |
| `needs_manual_review.csv` | Domains requiring human review |

---

##  Installation

```bash
git clone https://github.com/YOUR_USERNAME/domain-ownership-classifier.git
cd domain-ownership-classifier
pip install -r requirements.txt
```

---

##  Usage

Place your input files in the project root, then run:

```bash
python classifier.py
```

---

##  Requirements

pandas
requests
python-whois
openpyxl

Install all at once:
```bash
pip install pandas requests python-whois openpyxl
```

---

##  Configuration

To customize ownership keywords, edit this section in `classifier.py`:

```python
def ownership_keywords_found(text):
    keywords = ["gannett", "usatoday", "newsquest"]  # ← Add your keywords here
    return any(k in text for k in keywords)
```

---

##  License

MIT License — free to use and modify.
