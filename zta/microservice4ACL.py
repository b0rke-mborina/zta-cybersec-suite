from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import asyncio
import datetime
import json
from enum import Enum
from .utilityFunctions import checkIfPossibleDosAtack, getAuthData, handleAuthorization, sendRequest


app = FastAPI()


class Role(str, Enum):
	USER = "user"
	ADMIN = "admin"

class Data(BaseModel):
	user_id: int
	user_role: Role
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

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
	tasks = [handleAuthorization("ztaACL.db", data.user_id, data.user_role.value), checkIfPossibleDosAtack("ztaACL.db", 1)]
	[isAuthorized, isPossibleDosAtack] = await asyncio.gather(*tasks)
	return { "acl": "success", "is_authorized": isAuthorized, "is_possible_dos_atack": isPossibleDosAtack }
