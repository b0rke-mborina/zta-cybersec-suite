from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import asyncio
import datetime
from .utilityFunctions import isStringValid, sendRequest, storeReport


app = FastAPI()


class Data(BaseModel):
	timestamp: str
	logger_source: int
	user_id: str
	data: str
	checksum: str
	error_message: str

	@validator("timestamp")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

	@field_validator("user_id", "data", "checksum", "error_message")
	def validateAndSanitizeString(cls, v, info):
		regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' if info.field_name == "user_id" else r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$'
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "reporting": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/hashing/reporting", status_code = 200)
async def reporting(data: Data):
	dataForEncryption = data.model_dump()
	dataForEncryption["timestamp"] = dataForEncryption["timestamp"].translate(str.maketrans("\"'{}:", "_____"))

	userId = dataForEncryption["user_id"]
	del dataForEncryption["user_id"]

	tasks = [
		sendRequest(
			"get",
			"http://127.0.0.1:8086/zta/encrypt",
			{
				"data": dataForEncryption
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "WARN",
				"logger_source": 43,
				"user_id": data.user_id,
				"request": "__NULL__",
				"response": "__NULL__",
				"error_message": "Checksum verification failed. Checksum is invalid."
			}
		)
	]

	[orchestrationAutomationResult, monitoringResult] = await asyncio.gather(*tasks)
	if orchestrationAutomationResult[0].get("encryption") != "success" or monitoringResult[0].get("monitoring") != "success":
		raise HTTPException(500)
	
	reportData = orchestrationAutomationResult[0].get("data")
	reportData["user_id"] = userId
	await storeReport(reportData, "app4Reports.db")
	
	return { "reporting": "success" }
