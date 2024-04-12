from fastapi import FastAPI
from pydantic import BaseModel
from .utilityFunctions import storePassword, getPasswordInfo, hashPassword


app = FastAPI()


class Data(BaseModel):
	username: str
	password: str

@app.post("/password/store")
async def storage(data: Data):
	(passwordHash, salt, algorithm) = hashPassword(data.password)
	await storePassword("app5Data.db", 1, data.username, passwordHash, salt, algorithm)
	return { "storage": "success" }

@app.get("/password/retrieve")
async def retrieval(data: Data):
	(passwordHash, _, _) = hashPassword(data.password)
	passwordInfo = await getPasswordInfo("app5Data.db", 1, data.username, passwordHash)
	return { "retrieval": "success", "info": passwordInfo }
