from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
import datetime
import os
from utilityFunctions import getAuthData, hashPasswordWithSalt, isStringValid, sendRequest


app = FastAPI()


class Data(BaseModel):
	username: str
	password: str

	@field_validator("username", "password")
	def validateAndSanitizeString(cls, v, info):
		regex = r'^[a-zA-Z0-9._-]{3,20}$' if info.field_name == "username" else r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$'
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 52,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", os.getenv("URL_LOGGING_MICROSERVICE"), dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "verification": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		os.getenv("URL_GOVERNANCE_MICROSERVICE"),
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "verification": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/password/verify")
async def verification(request: Request, data: Data):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 52
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	response = { "verification": "success", "is_valid": True }

	retrievalResult = await sendRequest(
		"get",
		os.getenv("URL_STORAGE_MICROSERVICE_RETRIEVE"),
		{
			"user_id": userId,
			"username": data.username
		}
	)
	if retrievalResult[0].get("retrieval") != "success":
		raise HTTPException(500)
	
	retrievalResultInfo = retrievalResult[0].get("info")
	if len(retrievalResultInfo) == 0:
		response["is_valid"] = False
	
	passwordFromDbString = retrievalResultInfo[0][2]
	saltFromDbString = retrievalResultInfo[0][3]
	(passwordHash, _, _) = hashPasswordWithSalt(data.password, saltFromDbString)
	passwordHashString = passwordHash.decode("utf-8")
	if passwordHashString != passwordFromDbString:
		response["is_valid"] = False

	loggingResult = await sendRequest(
		"post",
		os.getenv("URL_LOGGING_MICROSERVICE"),
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 52,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
			"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
