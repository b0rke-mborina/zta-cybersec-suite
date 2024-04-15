from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import hashPassword


app = FastAPI()


class Data(BaseModel):
	username: str
	current_password: str
	new_password: str

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "reset": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/password/reset")
async def reset(data: Data):
	response = { "reset": "success" }

	(newPasswordHash, salt, algorithm) = hashPassword(data.new_password)

	return response
