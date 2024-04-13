from http.client import HTTPException
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import storePassword, getPasswordInfo, hashPassword


app = FastAPI()


class Data(BaseModel):
	username: str
	password: str

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "hashing": "failure", "error_message": "Unexpected error occured." },
	)

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
