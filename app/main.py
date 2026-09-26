from contextlib import asynccontextmanager
from io import BytesIO
from pathlib import Path

import pandas as pd
import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analyzer import MuleAnalyzer
from app.database import init_db


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

engine = MuleAnalyzer()
current_analysis = {
    "full_registry": {},
    "fraud_rings": [],
    "graph_elements": [],
    "summary": {},
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Quasar — Money Muling Detection",
    description="Graph-based analysis of transaction networks for suspicious patterns.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(TEMPLATE_DIR / "index.html")


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    global current_analysis

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    try:
        contents = await file.read()
        dataframe = pd.read_csv(BytesIO(contents))
        current_analysis = engine.process_data(dataframe)
        return current_analysis
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not analyze the uploaded file: {exc}",
        ) from exc


@app.get("/search")
async def search(id: str):
    account_id = id.strip()
    details = current_analysis["full_registry"].get(account_id)

    if details:
        return {"found": True, "details": details}

    return {"found": False}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
