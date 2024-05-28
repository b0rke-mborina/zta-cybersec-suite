from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
import asyncio
import datetime
from .utilityFunctions import getAppIdFromServiceAuthSource, getDataForIAM, isStringValid, sendRequest


app = FastAPI()


class AuthData(BaseModel):
	jwt: str
	username: str = ""
	password_hash: str = ""
	
	@field_validator("jwt", "username", "password_hash")
	def validateAndSanitizeString(cls, v, info):
		regex = None
		if info.field_name == "jwt":
			regex = r'^[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+\.|[A-Za-z0-9_-]+)+[A-Za-z0-9_-]+$'
		elif info.field_name == "password_hash":
			regex = r'^[a-fA-F0-9]{128}$'
		else:
			regex = r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$'

		allowNoneOrEmpty = False if info.field_name == "jwt" else True
		isValid = isStringValid(v, allowNoneOrEmpty, regex)

		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class Data(BaseModel):
	auth_data: AuthData
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
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": "__NULL__",
				"error_message": f"ZTA error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
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
		getDataForIAM(data.model_dump())
	)
	isAuthenticated = authenticationResult[0].get("is_authenticated")
	isAuthenticatedAdditionally = authenticationResult[0].get("is_authenticated_additionally")
	userId = authenticationResult[0].get("user_id")
	userRole = authenticationResult[0].get("user_role")
	if authenticationResult[0].get("iam") != "success":
		raise HTTPException(500)
	if isAuthenticated != True:
		raise RequestValidationError("User not allowed.")
	
	orchestrationAutomationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8086/zta/encrypt",
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
			"http://127.0.0.1:8082/zta/network",
			{
				"user_id": userId,
				"auth_source_app_id": authSourceAppId,
				"is_user_authenticated_additionally": isAuthenticatedAdditionally,
				"possible_breach": False
			}
		),
		sendRequest(
			"get",
			"http://127.0.0.1:8083/zta/acl",
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
	
	orchestrationAutomationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8086/zta/decrypt",
		{
			"data": {
				"user_id": userId,
				"role": userRole
			}
		}
	)
	if orchestrationAutomationResult[0].get("decryption") != "success":
		raise HTTPException(500)
	userIdForResponse = orchestrationAutomationResult[0].get("data").get("user_id")
	userRoleForResponse = orchestrationAutomationResult[0].get("data").get("role")
	
	response = {
		"tunnelling": "success",
		"is_authorized": isUserAllowed and isAuthorized and not isPossibleDosAtack,
		"user_id": userIdForResponse,
		"user_role": userRoleForResponse
	}

	tasksFinal = [
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
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
