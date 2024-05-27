from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import datetime
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
	is_user_authenticated_additionally: bool
	user_id: int = 0
	user_role: Role = "user"
	
	class Config:
		use_enum_values = True

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
