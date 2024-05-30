from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from enum import Enum
from .utilityFunctions import checkIfUserAllowed, isStringValid, sendRequest


app = FastAPI()


class Role(str, Enum):
	USER = "3DoxBhFdBD8=" # "user"
	ADMIN = "4I1FoHuYuxc=" # "admin"

class Data(BaseModel):
	user_id: str
	role: Role

	class Config:
		use_enum_values = True

	@validator("user_id")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
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
		content = { "access_control": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/digital-signature/access-control")
async def accessControler(data: Data):
	isAllowed = await checkIfUserAllowed("app3ACL.db", data.user_id, data.role)
	return { "access_control": "success", "is_allowed": isAllowed }
