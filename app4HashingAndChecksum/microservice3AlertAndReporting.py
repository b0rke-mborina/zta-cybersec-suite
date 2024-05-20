from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
from .utilityFunctions import sendRequest, storeReport


app = FastAPI()


class Data(BaseModel):
	timestamp: str
	logger_source: int
	user_id: int
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

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "reporting": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/hashing/reporting", status_code = 200)
async def reporting(data: Data):
	monitoringResult = await sendRequest(
		"post",
		"http://127.0.0.1:8087/zta/monitoring",
		{
			"timestamp": datetime.datetime.now().isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": "",
			"response": "",
			"error_message": "Checksum verification failed. Checksum is invalid."
		}
	)
	if monitoringResult[0].get("monitoring") != "success":
		raise HTTPException(500)

	await storeReport(data, "app4Reports.db")
	return { "reporting": "success" }
