from fastapi_scoring.scoring import compute_score

try:
    from fastapi import FastAPI
except ImportError:
    FastAPI = None

MESSAGE = "FastAPI stays Python. compute_score becomes Rust native."

app = FastAPI() if FastAPI is not None else None

if app is not None:

    @app.post("/score")
    def score(values: list[float]) -> dict[str, float | str]:
        return {"message": MESSAGE, "score": compute_score(values)}


def score_without_server(values: list[float]) -> dict[str, float | str]:
    return {"message": MESSAGE, "score": compute_score(values)}
