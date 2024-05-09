from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import checkUserNetworkSegment


app = FastAPI()


class Data(BaseModel):
	is_user_authenticated: bool
	user_id: int
	auth_source_app_id: int
	possible_breach: bool
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "network": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/network")
async def network(data: Data):
	isUserAuthprized = await checkUserNetworkSegment("ztaNetwork.db", data)
	return { "network": "success", "is_allowed": isUserAuthprized }
