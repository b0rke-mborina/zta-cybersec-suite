from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from enum import Enum
from .utilityFunctions import checkIfUserAllowed, sendRequest


app = FastAPI()


class Role(str, Enum):
	USER = "user"
	ADMIN = "admin"

class Data(BaseModel):
	user_id: int
	role: Role

	class Config:
		use_enum_values = True

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
	print(data)
	isAllowed = await checkIfUserAllowed("app3ACL.db", data.user_id, data.role)
	return { "access_control": "success", "is_allowed": isAllowed }
