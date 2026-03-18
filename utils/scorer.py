def calculate_risk(abuse_score: int | None, vt_malicious: int | None) -> tuple[int, str]:
    score = 0

    if abuse_score is not None:
        if abuse_score >= 90:
            score += 70
        elif abuse_score >= 50:
            score += 40
        elif abuse_score > 0:
            score += 15

    if vt_malicious is not None:
        if vt_malicious >= 10:
            score += 30
        elif vt_malicious >= 1:
            score += 15

    score = min(score, 100)

    if score >= 70:
        label = "Alto"
    elif score >= 40:
        label = "Medio"
    else:
        label = "Bajo"

    return score, label