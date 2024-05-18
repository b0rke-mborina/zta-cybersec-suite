from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import asyncio
import datetime
import json
from .utilityFunctions import getDataForIAM, sendRequest


app = FastAPI()


class Data(BaseModel):
	auth_type: str
	auth_data: dict
	auth_source: int

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	dataForMonitoringUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 5,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"ZTA error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8087/zta/monitoring", dataForMonitoringUnsuccessfulRequest)

	return JSONResponse(
		status_code = 500,
		content = { "tunnelling": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/tunnelling")
async def tunnelling(data: Data):
	print(data)
	print(getDataForIAM(data))
	authenticationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8081/zta/iam",
		getDataForIAM(data)
	)
	if authenticationResult[0].get("iam") != "success":
		raise HTTPException(500)
	if authenticationResult[0].get("is_authenticated") != True:
		raise RequestValidationError("User not allowed.")

	print(authenticationResult)
	isAuthenticated = authenticationResult[0].get("is_authenticated")
	userId = authenticationResult[0].get("user_id")
	userRole = authenticationResult[0].get("user_role")
	
	tasksAuthorization = [
		sendRequest(
			"get",
			"http://127.0.0.1:8082/zta/network",
			{
				"is_user_authenticated": isAuthenticated,
				"user_id": userId,
				"auth_source_app_id": data.auth_source,
				"possible_breach": False
			}
		),
		sendRequest(
			"get",
			"http://127.0.0.1:8083/zta/acl",
			{
				"task": "authorize",
				"user_id": userId,
				"user_role": userRole,
				"is_user_authenticated": isAuthenticated
			}
		)
	]

	[networkResult, aclResult] = await asyncio.gather(*tasksAuthorization)
	if networkResult[0].get("network") != "success" or aclResult[0].get("acl") != "success":
		raise HTTPException(500)
	
	isUserAllowed = networkResult[0].get("is_allowed")
	isAuthorized = aclResult[0].get("is_authorized")
	isPossibleDosAtack = aclResult[0].get("is_possible_dos_atack")
	response = { "tunnelling": "success", "is_authorized": isUserAllowed and isAuthorized and not isPossibleDosAtack }

	tasksFinal = [
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now().isoformat(),
				"level": "INFO",
				"logger_source": 4,
				"user_id": 1,
				"request": str(data),
				"response": str(response),
				"error_message": ""
			}
		)
	]

	if isPossibleDosAtack:
		tasksFinal.append(
			sendRequest(
				"post",
				"http://127.0.0.1:8080/zta/governance",
				{
					"problem": "dos_attack",
					"user_id": userId
				}
			)
		)

	results = await asyncio.gather(*tasksFinal)
	if results[0][0].get("monitoring") != "success":
		raise HTTPException(500)
	if len(results) == 2:
		if results[1][0].get("governance") != "success":
			raise HTTPException(500)

	return response
