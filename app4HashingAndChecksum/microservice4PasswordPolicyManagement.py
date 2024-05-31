from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import datetime
from .utilityFunctions import isStringValid, sendRequest, validatePassword


app = FastAPI()


class Data(BaseModel):
	user_id: str
	data: str

	@field_validator("user_id", "data")
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
		content = { "policy": "failure", "error_message": "Unexpected error occured." },
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
				"request": "__NULL__",
				"response": "__NULL__",
				"error_message": "Password validation failed. Passwod did not meet the requirements."
			}
		)
		if monitoringResult[0].get("monitoring") != "success":
			raise HTTPException(500)
	
	return { "policy": "success", "is_data_ok": isPasswordValid }
