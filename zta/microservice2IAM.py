from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from enum import Enum
from .utilityFunctions import handleUserAuthentication


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
	return JSONResponse(
		status_code = 500,
		content = { "iam": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/iam")
async def identityManagement(data: Data):
	(isUserAuthenticated, userId) = handleUserAuthentication("ztaUsers.db", data)
	return { "iam": "success", "is_authenticated": isUserAuthenticated, "user_id": userId }
