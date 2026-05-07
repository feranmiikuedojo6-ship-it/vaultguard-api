from fastapi import FastAPI
app = FastAPI()
@app.get("/")
def read_root():
    return {"status": "VaultGuard API is running"}
    from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
def read_root():
    return {"status": "VaultGuard API is running"}

# Example endpoint 1
@app.get("/hello/{name}")
def say_hello(name: str):
    return {"message": f"Hello {name}"}

# Example endpoint 2 - for login
class LoginData(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(data: LoginData):
    # Replace this with real logic later
    return {"email": data.email, "status": "logged in"}