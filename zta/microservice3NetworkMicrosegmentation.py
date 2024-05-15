from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import datetime
import json
from .utilityFunctions import checkUserNetworkSegment, sendRequest


app = FastAPI()


class Data(BaseModel):
	user_id: int
	auth_source_app_id: int
	is_user_authenticated: bool
	possible_breach: bool
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	dataForMonitoringUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 3,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"ZTA error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8087/zta/monitoring", dataForMonitoringUnsuccessfulRequest)

	return JSONResponse(
		status_code = 500,
		content = { "network": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/network")
async def network(data: Data):
	isUserAllowed = await checkUserNetworkSegment("ztaNetwork.db", data)
	return { "network": "success", "is_allowed": isUserAllowed }
