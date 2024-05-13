import datetime
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from enum import Enum
from .utilityFunctions import handleUserAuthentication, sendRequest


app = FastAPI()


class AuthMethod(str, Enum):
	USERNAME_AND_PASSWORD = "username_and_password"
	JWT = "jwt"

class Data(BaseModel):
	auth_method: AuthMethod
	auth_source: int
	username: str = ""
	passwordHash: str = ""
	jwt: str = ""
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	dataForMonitoringUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 2,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"ZTA error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8086/zta/monitoring", dataForMonitoringUnsuccessfulRequest)

	return JSONResponse(
		status_code = 500,
		content = { "iam": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/iam")
async def identityManagement(data: Data):
	(isUserAuthenticated, userId, userRole) = await handleUserAuthentication("ztaUsers.db", data)
	return { "iam": "success", "is_authenticated": isUserAuthenticated, "user_id": userId, "user_role": userRole }
