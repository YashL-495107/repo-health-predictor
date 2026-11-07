"""Calibration run: scan the repos from the backtest and measure how often the scanner raises STRONG findings."""
import argparse, os, time
import pandas as pd
from dotenv import load_dotenv
from github_client import GitHubClient, parse_repo
from repo_scan import scan_repo

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/backtest.csv")
    ap.add_argument("--output", default="data/scan_results.csv")
    ap.add_argument("--sleep", type=float, default=1.0)
    args = ap.parse_args()
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))
    repos = pd.read_csv(args.input)["repo"].tolist()
    rows = pd.read_csv(args.output).to_dict("records") if os.path.exists(args.output) else []
    done = {r["repo"] for r in rows}
    todo = [r for r in repos if r not in done]
    print(f"{len(done)} already scanned, {len(todo)} to go")
    for i, full in enumerate(todo, 1):
        owner, name = parse_repo(full)
        t0 = time.time()
        res = scan_repo(client, owner, name)
        rows.append({
            "repo": full, "ran": res["ran"], "strong": res["strong"], "review": res["review"], 
            "known_malicious_count": res.get("known_malicious_count", 0),
            "high_risk_pattern_count": res.get("high_risk_pattern_count", 0),
            "code_high": res["code_high"], "secrets_strong": res["secrets_strong"],
            "seconds": round(time.time() - t0, 1)
        })
        pd.DataFrame(rows).to_csv(args.output, index=False)
        print(f"[{i}/{len(todo)}] {full}: KM={res.get('known_malicious_count', 0)} HR={res.get('high_risk_pattern_count', 0)} ({rows[-1]['seconds']}s)")
        time.sleep(args.sleep)

if __name__ == "__main__": main()