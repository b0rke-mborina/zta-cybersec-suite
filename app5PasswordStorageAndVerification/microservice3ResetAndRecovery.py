from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


class Data(BaseModel):
	username: str
	current_password: str
	new_password: str

@app.get("/password/reset")
async def reset(data: Data):
	return {"status": "OK"}
