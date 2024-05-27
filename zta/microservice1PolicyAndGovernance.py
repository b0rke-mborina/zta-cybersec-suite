from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum
from .utilityFunctions import handleProblem, sendRequest


app = FastAPI()


class Problem(str, Enum):
	SECURITY_BREACH = "security_breach"
	DOS_ATTACK = "dos_attack"
	DATA_INCONSISTENCY = "data_inconsistency"
	DATA_COMPROMISE = "data_compromise"
	INFRASTRUCTURE_INTEGRITY_VIOLATION = "infrastructure_integrity_violation"
	PARTIAL_SYSTEM_FAILURE = "partial_system_failure"
	TOTAL_SYSTEM_FAILURE = "total_system_failure"

class Data(BaseModel):
	problem: Problem
	user_id: int = 0
	
	class Config:
		use_enum_values = True

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	body = await request.body()
	dataForMonitoringUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "FATAL",
		"logger_source": 1,
		"user_id": body.user_id,
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {body}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"ZTA error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", "http://127.0.0.1:8087/zta/monitoring", dataForMonitoringUnsuccessfulRequest)

	return JSONResponse(
		status_code = 500,
		content = { "governance": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/zta/governance")
async def governance(request: Request, data: Data):
	response = { "governance": "success" }
	await handleProblem(request, data, response)
	return response
