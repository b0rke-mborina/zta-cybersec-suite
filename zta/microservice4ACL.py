from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import datetime
import json
from enum import Enum
from .utilityFunctions import handleACLTask, sendRequest


app = FastAPI()


class Task(str, Enum):
	AUTHORIZE = "authorize"
	DENY_ACCESS_TO_ALL = "deny_access_to_all"
	DENY_ACCESS_TO_USERS = "deny_access_to_users"
	DENY_ACCESS_TO_USER = "deny_access_to_user"

class Role(str, Enum):
	USER = "user"
	ADMIN = "admin"

class Data(BaseModel):
	task: Task
	is_user_authenticated: bool
	user_id: int = 0
	user_role: Role = "user"

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	dataForMonitoringUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 4,
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

@app.get("/zta/acl")
async def tunnelling(data: Data):
	[isAuthorized, isPossibleDosAtack] = await handleACLTask("ztaACL.db", data)
	return { "acl": "success", "is_authorized": isAuthorized, "is_possible_dos_atack": isPossibleDosAtack }
