from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.routers import auth, user, settings

app = FastAPI(title="Code Repair Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(user.router, prefix="/api/v1/users", tags=["users"])
app.include_router(settings.router, prefix="/api/v1/settings", tags=["settings"])


@app.get("/")
def read_root():
    return {"message": "Code Repair Backend API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}