from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import asyncio
import datetime
import json
from .utilityFunctions import getAuthData, sendRequest


app = FastAPI()


class Data(BaseModel):
	headers: dict
	auth_source: int
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

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
	(authType, authData) = getAuthData(data.headers)

	authenticationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8081/zta/iam",
		{
			"auth_method": authType,
			"auth_source": data.auth_source,
			"username": authData.get("username") if authData.get("username") is not None else "",
			"passwordHash": authData.get("password") if authData.get("password") is not None else "",
			"jwt": authData.get("jwt") if authData.get("jwt") is not None else ""
		}
	)
	if authenticationResult[0].get("iam") != "success":
		raise HTTPException(500)
	
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
				"user_role": userRole
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
