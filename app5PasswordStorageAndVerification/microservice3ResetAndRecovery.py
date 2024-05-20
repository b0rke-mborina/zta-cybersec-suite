from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from .utilityFunctions import getAuthData, hashPasswordWithSalt, sendRequest


app = FastAPI()


class Data(BaseModel):
	username: str
	current_password: str
	new_password: str

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "INFO",
		"logger_source": 3,
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
			"auth_source": 1
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")

	policyResult = await sendRequest(
		"get",
		"http://127.0.0.1:8043/password/policy",
		{
			"data": data.new_password
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
			"user_id": 1,
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

	updateResult = await sendRequest(
		"post",
		"http://127.0.0.1:8040/password/update",
		{
			"user_id": 1,
			"username": data.username,
			"password_hash": newPasswordHashString,
			"salt": salt,
			"algorithm": algorithm
		}
	)
	if updateResult[0].get("update") != "success":
		raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8044/password/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
