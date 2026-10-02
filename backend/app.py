"""FastAPI application factory for the Network IDS Simulation."""
from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from ids.feature_extractor import FlowValidationError
from backend.database import Database
from backend.routes.api import router
from backend.services.ids_service import IDSService

load_dotenv()  # Loads local .env when present; production should inject secrets securely.

def create_app(db_path=None,dataset_path=None,model_path=None,ml_enabled=None):
    app=FastAPI(title="Network IDS Simulation API",version="1.0.0",description="Defensive API for synthetic network-flow analysis. No packet generation or blocking functionality.")
    origins=[o.strip() for o in os.getenv("CORS_ORIGINS","http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]
    app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=False,allow_methods=["GET","POST","PUT"],allow_headers=["Content-Type","X-API-Key","X-Role"])
    db=Database(db_path or os.getenv("DATABASE_PATH","data/ids.db")); service=IDSService(db,dataset_path or os.getenv("DATASET_PATH","data/network_traffic.csv"),model_path or os.getenv("MODEL_PATH","models/ids_rf.joblib"),ml_enabled if ml_enabled is not None else os.getenv("ML_ENABLED","true").lower()=="true")
    app.state.db=db; app.state.ids=service
    app.include_router(router)
    @app.get("/health")
    def health(): return {"status":"ok","mode":"defensive-synthetic-only","ml_enabled":service.ml.enabled}
    @app.exception_handler(FlowValidationError)
    async def validation_error(_:Request,exc:FlowValidationError): return JSONResponse(status_code=422,content={"detail":str(exc)})
    @app.exception_handler(Exception)
    async def server_error(_:Request,exc:Exception):
        # Avoid exposing stack traces or internals to API clients.
        return JSONResponse(status_code=500,content={"detail":"internal server error"})
    return app

app=create_app()
if __name__=="__main__":
    import uvicorn
    uvicorn.run("backend.app:app",host="0.0.0.0",port=int(os.getenv("PORT","8000")),reload=False)
