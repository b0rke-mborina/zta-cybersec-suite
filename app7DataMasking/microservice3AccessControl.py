from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from enum import Enum
from .utilityFunctions import checkIfUserAllowed


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
	return JSONResponse(
		status_code = 500,
		content = { "access_control": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/data/access-control")
async def accessControl(data: Data):
	isAllowed = await checkIfUserAllowed("app7ACL.db", data.user_id, data.role)
	return { "access_control": "success", "is_allowed": isAllowed }
