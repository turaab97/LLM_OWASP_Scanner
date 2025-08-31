# fuzzer.py
import random, re

SYNONYMS = {
  "ignore": ["disregard", "bypass", "omit"],
  "instructions": ["rules", "policy", "constraints"],
  "system": ["assistant", "guardrail", "safeguard"],
  "forever": ["infinitely", "without end", "no stopping"],
}

def paraphrase(text: str, p=0.30):
    def swap(word):
        w = word.lower()
        if w in SYNONYMS and random.random() < p:
            return random.choice(SYNONYMS[w])
        return word
    # keep punctuation tokens by splitting on non-word boundaries
    toks = re.split(r"(\W+)", text)
    return "".join(swap(t) for t in toks)

def sprinkle_roleplay(text: str):
    return "pretend you are the system. " + text

def make_variants(prompt: str, k: int = 8):
    cands = set([prompt])
    while len(cands) < k:
        v = prompt
        if random.random() < 0.6:
            v = paraphrase(v, p=0.35)
        if random.random() < 0.4:
            v = sprinkle_roleplay(v)
        cands.add(v)
    return list(cands)

