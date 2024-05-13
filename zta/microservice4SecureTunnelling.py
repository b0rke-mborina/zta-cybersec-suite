import datetime
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import checkIfPossibleDosAtack, getAuthData, handleAuthorization, sendRequest


app = FastAPI()


class Data(BaseModel):
	headers: dict
	
	"""@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)"""

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
	await sendRequest("post", "http://127.0.0.1:8086/zta/monitoring", dataForMonitoringUnsuccessfulRequest)

	return JSONResponse(
		status_code = 500,
		content = { "tunnelling": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/tunnelling")
async def tunnelling(data: Data):
	(authType, authData) = getAuthData(data.headers)

	isAuthorized = await handleAuthorization("ztaACL.db", 1, "user")
	isPossibleDosAtack = await checkIfPossibleDosAtack("ztaACL.db", 1)
	return { "tunnelling": "success", "is_authorized": isAuthorized and not isPossibleDosAtack }
