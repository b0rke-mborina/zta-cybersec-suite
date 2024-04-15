from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import hashPassword


app = FastAPI()


class Data(BaseModel):
	username: str
	password: str

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "verification": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/password/verify")
async def verification(data: Data):
	(passwordHash, _, _) = hashPassword(data.password)
	response = { "verification": "success", "is_valid": True }

	retrievalResponse = {}
	retrievalResponseInfo = retrievalResponse.get("info")
	if len(retrievalResponseInfo) == 0:
		response["is_valid"] = False
	
	return response
