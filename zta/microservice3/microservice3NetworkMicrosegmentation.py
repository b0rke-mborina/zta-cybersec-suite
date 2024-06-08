from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
import os
from utilityFunctions import checkUserNetworkSegment, isStringValid, sendRequest


app = FastAPI()


class Data(BaseModel):
	user_id: str
	auth_source_app_id: str
	is_user_authenticated_additionally: str
	possible_breach: bool

	@validator("user_id", "auth_source_app_id", "is_user_authenticated_additionally")
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
			os.getenv("URL_MONITORING_MICROSERVICE"),
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 3,
				"user_id": body.user_id,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {body}".translate(str.maketrans("\"'{}:", "_____")),
				"response": "__NULL__",
				"error_message": f"ZTA error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
			}
		),
		sendRequest(
			"post",
			os.getenv("URL_GOVERNANCE_MICROSERVICE"),
			{
				"problem": "total_system_failure"
			}
		)
	]
	await asyncio.gather(*tasks)

	return JSONResponse(
		status_code = 500,
		content = { "network": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/network")
async def network(data: Data):
	isUserAllowed = await checkUserNetworkSegment("ztaNetwork.db", data)
	return { "network": "success", "is_allowed": isUserAllowed }
