"""Small statistics for judging random-search engines honestly (stdlib only).

A stateful/race/fuzz engine that finds a bug in k of n independent runs has a detection rate somewhere in a wide interval;
a run that finds nothing proves little. Sources: Wilson (1927) interval; the "rule of three" for zero events; Klees et al.,
"Evaluating Fuzz Testing" (CCS 2018): repeated trials and variance, not one lucky run.
"""
import math


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    """95% Wilson score interval for k successes in n independent trials -> (low, high)."""
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def miss_bound(n: int, confidence: float = 0.95) -> float:
    """Upper bound on the per-run rate of an event never seen in n independent runs (one-sided, `confidence`).

    n=10 clean runs -> a bug that shows up in up to ~26% of runs could still be hiding (exact; the rule of three says 3/n = 30%).
    It bounds the rate; it is not the chance that the next run fails.
    """
    if n <= 0:
        return 1.0
    return 1 - (1 - confidence) ** (1 / n)


def runs_needed(rate: float, confidence: float = 0.95) -> int:
    """Independent clean runs needed before a bug with per-run detection `rate` is ruled out at `confidence`."""
    if not 0 < rate < 1:
        raise ValueError("rate must be in (0, 1)")
    return math.ceil(math.log(1 - confidence) / math.log(1 - rate))


def attempts_for(rate: float, target: float = 0.99) -> int:
    """Attempts (independent tries) so that a bug with per-try detection `rate` is found with probability >= target."""
    return runs_needed(rate, confidence=target)


def describe(k: int, n: int) -> str:
    """'3/8 seeds (95% CI 14%-69%)' or, with k == 0, a bound on what could still be hiding."""
    if k == 0:
        return f"0/{n} runs: a bug found in up to {miss_bound(n):.0%} of runs could still be hiding"
    lo, hi = wilson(k, n)
    return f"{k}/{n} runs (95% CI {lo:.0%}-{hi:.0%})"
