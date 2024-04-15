from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from .utilityFunctions import hashPassword, sendRequest


app = FastAPI()


class Data(BaseModel):
	username: str
	password: str

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 2,
		"user_id": 1,
		"request": str(request),
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8044/password/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "verification": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "verification": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/password/verify")
async def verification(data: Data):
	(passwordHash, _, _) = hashPassword(data.password)
	response = { "verification": "success", "is_valid": True }

	retrievalResponse = {"info": [("data")]}
	retrievalResponseInfo = retrievalResponse.get("info")[0]
	if len(retrievalResponseInfo) == 0:
		response["is_valid"] = False
	
	return response
