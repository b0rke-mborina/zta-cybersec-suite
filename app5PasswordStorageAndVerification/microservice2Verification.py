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
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
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

	retrievalResult = sendRequest(
		"get",
		"http://127.0.0.1:8040/password/retrieve",
		{
			"user_id": 1,
			"username": data.username,
			"password_hash": passwordHash
		}
	)
	if retrievalResult[0].get("retrieval") != "success":
		raise HTTPException(500)

	retrievalResultInfo = retrievalResult[0].get("info")
	if len(retrievalResultInfo) == 0:
		response["is_valid"] = False
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8044/password/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
