from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import datetime
import os
from utilityFunctions import getAppIdFromServiceAuthSource, getDataForIAM, sendRequest, validateData


app = FastAPI()


class AuthData(BaseModel):
	jwt: str = ""
	username: str = ""
	password_hash: str = ""

class Data(BaseModel):
	auth_data: AuthData
	auth_source: int

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	tasks = [
		sendRequest(
			"post",
			os.getenv("URL_MONITORING_MICROSERVICE"),
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 5,
				"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user cannot be authenticated
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": "__NULL__",
				"error_message": f"ZTA error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
			}
		),
		sendRequest(
			"post",
			os.getenv("URL_GOVERNANCE_MICROSERVICE"),
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
	isDataValid = validateData(data)
	if not isDataValid:
		return { "tunnelling": "success", "is_authorized": False }

	dataForIAM = getDataForIAM(data.model_dump())
	authenticationResult = await sendRequest(
		"get",
		os.getenv("URL_IAM_MICROSERVICE"),
		dataForIAM
	)
	isAuthenticated = authenticationResult[0].get("is_authenticated")
	isAuthenticatedAdditionally = authenticationResult[0].get("is_authenticated_additionally")
	userId = authenticationResult[0].get("user_id")
	userRole = authenticationResult[0].get("user_role")
	if authenticationResult[0].get("iam") != "success":
		raise HTTPException(500)
	if isAuthenticated != True:
		return { "tunnelling": "success", "is_authorized": False }
	
	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_source_app_id": getAppIdFromServiceAuthSource(data.auth_source),
				"is_user_authenticated_additionally": isAuthenticatedAdditionally,
				"task": "authorize"
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	authSourceAppId = orchestrationAutomationResult[0].get("data").get("auth_source_app_id")
	isAuthenticatedAdditionally = orchestrationAutomationResult[0].get("data").get("is_user_authenticated_additionally")
	task = orchestrationAutomationResult[0].get("data").get("task")

	tasksAuthorization = [
		sendRequest(
			"get",
			os.getenv("URL_NETWORK_MICROSERVICE"),
			{
				"user_id": userId,
				"auth_source_app_id": authSourceAppId,
				"is_user_authenticated_additionally": isAuthenticatedAdditionally,
				"possible_breach": False
			}
		),
		sendRequest(
			"get",
			os.getenv("URL_ACL_MICROSERVICE"),
			{
				"task": task,
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
	
	response = {
		"tunnelling": "success",
		"is_authorized": isUserAllowed and isAuthorized and not isPossibleDosAtack,
		"user_id": userId,
		"user_role": userRole
	}

	tasksFinal = [
		sendRequest(
			"post",
			os.getenv("URL_MONITORING_MICROSERVICE"),
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 5,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": "__NULL__"
			}
		)
	]

	if isPossibleDosAtack:
		tasksFinal.append(
			sendRequest(
				"post",
				os.getenv("URL_GOVERNANCE_MICROSERVICE"),
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
