from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from .utilityFunctions import handleUserAuthentication, isStringValid, sendRequest


app = FastAPI()


class Data(BaseModel):
	jwt: str
	username: str = ""
	password_hash: str = ""

	@validator("jwt", "username", "password_hash")
	def validateAndSanitizeString(cls, v, field):
		allowNoneOrEmpty = False if field.name == "jwt" else True
		isValid = isStringValid(v, allowNoneOrEmpty, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 2,
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
		content = { "iam": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/iam")
async def identityManagement(data: Data):
	(isUserAuthenticated, isUserAuthenticatedAdditionally, userId, userRole) = await handleUserAuthentication("ztaUsers.db", data)
	return {
		"iam": "success",
		"is_authenticated": isUserAuthenticated, "is_authenticated_additionally": isUserAuthenticatedAdditionally,
		"user_id": userId, "user_role": userRole
	}
