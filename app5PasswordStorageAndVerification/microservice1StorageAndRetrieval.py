from http.client import HTTPException
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import storePasswordHash, getPasswordHashInfo, updatePasswordHash, hashPassword


app = FastAPI()


class DataStore(BaseModel):
	username: str
	password: str

class DataRetrieve(BaseModel):
	user_id: str
	username: str
	password_hash: str

class DataUpdate(BaseModel):
	user_id: str
	username: str
	password_hash: str
	salt: str
	algorithm: str

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/password/store")
async def storage(data: DataStore):
	(passwordHash, salt, algorithm) = hashPassword(data.password)
	await storePasswordHash("app5Data.db", 1, data.username, passwordHash, salt, algorithm)
	return { "storage": "success" }

@app.get("/password/retrieve")
async def retrieval(data: DataRetrieve):
	passwordInfo = await getPasswordHashInfo("app5Data.db", data.user_id, data.username, data.password_hash)
	return { "retrieval": "success", "info": passwordInfo }

@app.post("/password/update")
async def storage(data: DataUpdate):
	await updatePasswordHash("app5Data.db", data.user_id, data.username, data.password_hash, data.salt, data.algorithm)
	return { "update": "success" }
