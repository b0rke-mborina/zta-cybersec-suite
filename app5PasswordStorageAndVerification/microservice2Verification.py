from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


class Data(BaseModel):
	username: str
	password: str

@app.get("/password/verify")
async def verification(data: Data):
	return {"status": "OK"}
