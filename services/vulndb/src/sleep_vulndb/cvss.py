"""CVSS v3.x base score calculation and severity bands.

OSV records carry CVSS vectors, not scores. The base score is a pure function
of the vector, so it is computed here following the CVSS v3.1 specification
(section 7) instead of being taken from yet another source.
"""

import math


class InvalidVector(ValueError):
    pass


_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PRIVILEGES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number >= value, float-safe."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        raise InvalidVector(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise InvalidVector(f"malformed metric {part!r} in {vector!r}")
        name, value = part.split(":", 1)
        metrics[name] = value
    missing = [name for name in _REQUIRED if name not in metrics]
    if missing:
        raise InvalidVector(f"missing base metrics {missing} in {vector!r}")
    return metrics


def base_score(vector: str) -> float:
    metrics = parse_vector(vector)
    try:
        scope = metrics["S"]
        privileges = _PRIVILEGES[scope][metrics["PR"]]
        weights = {name: _WEIGHTS[name][metrics[name]] for name in _WEIGHTS}
    except KeyError as error:
        raise InvalidVector(f"unknown metric value in {vector!r}") from error

    iss = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges * weights["UI"]

    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def severity_from_score(score: float) -> str:
    """Qualitative CVSS v3 rating mapped to the SLeep severity scale."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# Ubuntu priorities (https://ubuntu.com/security/cves/about#priority).
VENDOR_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
}
