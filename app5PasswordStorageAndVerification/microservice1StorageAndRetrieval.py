from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import asyncio
import datetime
from .utilityFunctions import getAuthData, isStringValid, sendRequest, storePasswordHash, getPasswordHashInfo, updatePasswordHash, hashPassword


app = FastAPI()


class DataStore(BaseModel):
	username: str
	password: str

	@field_validator("username", "password")
	def validateAndSanitizeString(cls, v, info):
		regex = r'^[a-zA-Z0-9._-]{3,20}$' if info.field_name == "username" else r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$'
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataRetrieve(BaseModel):
	user_id: int
	username: str

	@validator("username")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[a-zA-Z0-9._-]{3,20}$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataUpdate(BaseModel):
	user_id: str
	username: str
	password_hash: str
	salt: str
	algorithm: str

	@validator("user_id", "username", "password_hash", "salt", "algorithm")
	def validateAndSanitizeString(cls, v, info):
		regex = r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$'
		if info.field_name == "user_id":
			regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
		elif info.field_name == "username":
			regex = r'^[a-zA-Z0-9._-]{3,20}$'
		elif info.field_name == "password_hash":
			regex = r'^\$2[aby]\$[0-3][0-9]\$[./A-Za-z0-9]{22}[./A-Za-z0-9]{31}$'
		elif info.field_name == "salt":
			regex = r'^[./A-Za-z0-9]{22}$'

		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 51,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", "http://127.0.0.1:8044/password/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "storage": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/password/store")
async def storage(request: Request, data: DataStore):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 51
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
			"data": data.password,
			"user_id": userId
		}
	)
	if policyResult[0].get("policy") != "success":
		raise HTTPException(500)
	if not policyResult[0].get("is_data_ok"):
		raise RequestValidationError("Password requirements not fulfilled.")

	(passwordHash, salt, algorithm) = hashPassword(data.password)
	passwordHashString = passwordHash.decode("utf-8")
	saltString = salt.decode("utf-8")
	response = { "storage": "success" }
	
	tasks = [
		storePasswordHash("app5Data.db", userId, data.username, passwordHashString, saltString, algorithm),
		sendRequest(
			"post",
			"http://127.0.0.1:8044/password/logging",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 51,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[1][0].get("logging") != "success":
		raise HTTPException(500)

	return response

@app.get("/password/retrieve")
async def retrieval(data: DataRetrieve):
	passwordInfo = await getPasswordHashInfo("app5Data.db", data.user_id, data.username)
	return { "retrieval": "success", "info": passwordInfo }

@app.post("/password/update")
async def storage(data: DataUpdate):
	await updatePasswordHash("app5Data.db", data.user_id, data.username, data.password_hash, data.salt, data.algorithm)
	return { "update": "success" }
