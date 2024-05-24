from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
from .utilityFunctions import isStringValid, sendRequest, validatePassword


app = FastAPI()


class Data(BaseModel):
	data: str
	user_id: int

	@validator("data")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
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
		content = { "policy_management": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/hashing/policy", status_code = 200)
async def reporting(data: Data):
	isPasswordValid = validatePassword(data.data)
	
	if not isPasswordValid:
		monitoringResult = await sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "WARN",
				"logger_source": 44,
				"user_id": data.user_id,
				"request": "",
				"response": "",
				"error_message": "Password validation failed. Passwod did not meet the requirements."
			}
		)
		if monitoringResult[0].get("monitoring") != "success":
			raise HTTPException(500)
	
	return { "policy_management": "success", "is_data_ok": isPasswordValid }
