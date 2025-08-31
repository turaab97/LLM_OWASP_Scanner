# policy_engine.py
import re, yaml
from typing import List, Dict

class PolicyEngine:
    def __init__(self, path="policy.yaml"):
        with open(path, "r") as f:
            self.cfg = yaml.safe_load(f)
        self.rules = self.cfg.get("rules", [])

    def evaluate(self, text: str) -> List[Dict]:
        hits = []
        for r in self.rules:
            block = r.get("match", {})
            found = False
            if "any" in block:
                for cond in block["any"]:
                    if "regex" in cond and re.search(cond["regex"], text, re.IGNORECASE):
                        found = True; break
            if found:
                hits.append({
                    "id": r["id"],
                    "name": r["name"],
                    "severity": r["severity"],
                    "rationale": r["rationale"],
                    "recommendation": r["recommendation"],
                })
        return hits

