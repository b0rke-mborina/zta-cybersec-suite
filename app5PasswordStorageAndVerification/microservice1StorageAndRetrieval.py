from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import datetime
import json
from .utilityFunctions import sendRequest, storePasswordHash, getPasswordHashInfo, updatePasswordHash, hashPassword


app = FastAPI()


class DataStore(BaseModel):
	username: str
	password: str

class DataRetrieve(BaseModel):
	user_id: int
	username: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

class DataUpdate(BaseModel):
	user_id: int
	username: str
	password_hash: str
	salt: str
	algorithm: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 1,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8044/password/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "storage": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/password/store")
async def storage(data: DataStore):
	policyResult = await sendRequest(
		"get",
		"http://127.0.0.1:8043/password/policy",
		{
			"data": data.password
		}
	)
	if policyResult[0].get("policy") != "success":
		raise HTTPException(500)
	if not policyResult[0].get("is_data_ok"):
		raise RequestValidationError("Password requirements not fulfilled.")

	(passwordHash, salt, algorithm) = hashPassword(data.password)
	passwordHashString = passwordHash.decode("utf-8")
	saltString = salt.decode("utf-8")
	await storePasswordHash("app5Data.db", 1, data.username, passwordHashString, saltString, algorithm)
	response = { "storage": "success" }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8044/password/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response

@app.get("/password/retrieve")
async def retrieval(data: DataRetrieve):
	passwordInfo = await getPasswordHashInfo("app5Data.db", data.user_id, data.username)
	return { "retrieval": "success", "info": passwordInfo }

@app.post("/password/update")
async def storage(data: DataUpdate):
	await updatePasswordHash("app5Data.db", data.user_id, data.username, data.password_hash, data.salt, data.algorithm)
	return { "update": "success" }
