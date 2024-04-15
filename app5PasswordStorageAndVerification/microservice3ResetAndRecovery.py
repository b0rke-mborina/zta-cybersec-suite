from fastapi import FastAPI
from pydantic import BaseModel
from .utilityFunctions import hashPassword


app = FastAPI()


class Data(BaseModel):
	username: str
	current_password: str
	new_password: str

@app.get("/password/reset")
async def reset(data: Data):
	response = { "reset": "success" }

	(newPasswordHash, salt, algorithm) = hashPassword(data.new_password)

	return response
