from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import datetime
from .utilityFunctions import getAppIdFromServiceAuthSource, getDataForIAM, sendRequest


app = FastAPI()


class Data(BaseModel):
	auth_data: dict
	auth_source: int

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 5,
				"user_id": 0, # placeholder value is used because user cannot be authenticated
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": "",
				"error_message": f"ZTA error. {exc}"
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8080/zta/governance",
			{
				"problem": "total_system_failure"
			}
		)
	]
	await asyncio.gather(*tasks)

	return JSONResponse(
		status_code = 500,
		content = { "tunnelling": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/tunnelling")
async def tunnelling(request: Request, data: Data):
	authenticationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8081/zta/iam",
		getDataForIAM(data)
	)
	isAuthenticated = authenticationResult[0].get("is_authenticated")
	isAuthenticatedAdditionally = authenticationResult[0].get("is_authenticated_additionally")
	userId = authenticationResult[0].get("user_id")
	userRole = authenticationResult[0].get("user_role")
	if authenticationResult[0].get("iam") != "success":
		raise HTTPException(500)
	if isAuthenticated != True:
		raise RequestValidationError("User not allowed.")

	
	tasksAuthorization = [
		sendRequest(
			"get",
			"http://127.0.0.1:8082/zta/network",
			{
				"is_user_authenticated_additionally": isAuthenticatedAdditionally,
				"user_id": userId,
				"auth_source_app_id": getAppIdFromServiceAuthSource(data.auth_source),
				"possible_breach": False
			}
		),
		sendRequest(
			"get",
			"http://127.0.0.1:8083/zta/acl",
			{
				"task": "authorize",
				"is_user_authenticated_additionally": isAuthenticatedAdditionally,
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
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 5,
				"user_id": 1, # PLACEHOLDER
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
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
