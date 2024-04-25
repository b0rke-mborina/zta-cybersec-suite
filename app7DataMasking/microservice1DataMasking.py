from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from .utilityFunctions import maskData, sendRequest, checkData


app = FastAPI()


class DataMask(BaseModel):
	dataset: str
	data: list

class DataUnmask(BaseModel):
	dataset: str

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
	await sendRequest("post", "http://127.0.0.1:8063/data/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "storage": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "sharing": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/data/mask")
async def masking(data: DataMask):
	checkData(data.data)
	print(maskData(data.data))
	return { "masking": "success" }

@app.get("/data/unmask")
async def unmasking(data: DataUnmask):
	return { "unmasking": "success" }
