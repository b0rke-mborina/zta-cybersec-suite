from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import datetime
from .utilityFunctions import checkUserNetworkSegment, sendRequest


app = FastAPI()


class Data(BaseModel):
	user_id: int
	auth_source_app_id: int
	is_user_authenticated_additionally: bool
	possible_breach: bool

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
				"logger_source": 3,
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
		content = { "network": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/network")
async def network(data: Data):
	isUserAllowed = await checkUserNetworkSegment("ztaNetwork.db", data)
	return { "network": "success", "is_allowed": isUserAllowed }
