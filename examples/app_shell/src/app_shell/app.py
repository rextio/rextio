from app_shell.scoring import compute_score

MESSAGE = "Application shell stays Python. compute_score becomes Rust native."


def score_from_shell(values: list[float]) -> dict[str, float | str]:
    return {"message": MESSAGE, "score": compute_score(values)}
