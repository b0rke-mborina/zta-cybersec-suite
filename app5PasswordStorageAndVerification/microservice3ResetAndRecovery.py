from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from .utilityFunctions import getAuthData, hashPasswordWithSalt, isStringValid, sendRequest


app = FastAPI()


class Data(BaseModel):
	username: str
	current_password: str
	new_password: str

	@validator("username", "current_password", "new_password")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 53,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
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
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "reset": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/password/reset")
async def reset(request: Request, data: Data):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 53
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	policyResult = await sendRequest(
		"get",
		"http://127.0.0.1:8043/password/policy",
		{
			"data": data.new_password,
			"user_id": userId
		}
	)
	if policyResult[0].get("policy") != "success":
		raise HTTPException(500)
	if not policyResult[0].get("is_data_ok"):
		raise RequestValidationError("Password requirements not fulfilled.")

	retrievalResult = await sendRequest(
		"get",
		"http://127.0.0.1:8040/password/retrieve",
		{
			"user_id": userId,
			"username": data.username
		}
	)
	if retrievalResult[0].get("retrieval") != "success":
		raise HTTPException(500)
	if len(retrievalResult[0].get("info")) == 0:
		raise RequestValidationError("Wrong password to change.")
	
	response = { "reset": "success" }
	
	passwordFromDbString = retrievalResult[0].get("info")[0][2]
	saltFromDbString = retrievalResult[0].get("info")[0][3]
	(currentPasswordHash, _, _) = hashPasswordWithSalt(data.current_password, saltFromDbString)
	currentPasswordHashString = currentPasswordHash.decode("utf-8")
	(newPasswordHash, salt, algorithm) = hashPasswordWithSalt(data.new_password, saltFromDbString)
	newPasswordHashString = newPasswordHash.decode("utf-8")

	if currentPasswordHashString != passwordFromDbString:
		raise RequestValidationError("Current password invalid.")
	
	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8040/password/update",
			{
				"user_id": userId,
				"username": data.username,
				"password_hash": newPasswordHashString,
				"salt": salt,
				"algorithm": algorithm
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8044/password/logging",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 53,
				"user_id": userId,
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": str(response),
				"error_message": ""
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("update") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
