from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from enum import Enum
from .utilityFunctions import handleACLTask, isStringValid, sendRequest


app = FastAPI()


class Task(str, Enum):
	AUTHORIZE = "eZ9FPVVabeN6dDFRZ9itdA=="
	DENY_ACCESS_TO_ALL = "r+KhlYVgRAQABXy35o6JOCACeHZG6q5o"
	DENY_ACCESS_TO_USERS = "r+KhlYVgRAQI7B9eX5vQoBZazil7VuSO"
	DENY_ACCESS_TO_USER = "r+KhlYVgRAQI7B9eX5vQoKm6HFXK1u4G"

class Role(str, Enum):
	USER = "3DoxBhFdBD8="
	ADMIN = "4I1FoHuYuxc="

class Data(BaseModel):
	task: Task
	user_id: str
	user_role: Role
	is_user_authenticated_additionally: str
	
	class Config:
		use_enum_values = True

	@validator("task", "user_id", "is_user_authenticated_additionally")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')

		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	body = await request.body()
	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 4,
				"user_id": body.user_id,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {body}".translate(str.maketrans("\"'{}:", "_____")),
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

@app.get("/zta/acl")
async def acl(data: Data):
	[isAuthorized, isPossibleDosAtack] = await handleACLTask("ztaACL.db", data)
	return { "acl": "success", "is_authorized": isAuthorized, "is_possible_dos_atack": isPossibleDosAtack }
