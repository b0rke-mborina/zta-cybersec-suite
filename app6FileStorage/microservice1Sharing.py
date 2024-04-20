from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from enum import Enum


app = FastAPI()


class Format(str, Enum):
	TXT = "txt"
	BASE64 = "base64"

class DataStore(BaseModel):
	format: Format
	filename: str
	file: str

class DataRetrieve(BaseModel):
	filename: str

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "sharing": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/file/store")
async def storage(data: DataStore):
	return { "storage": "success" }

@app.get("/file/retrieve")
async def retrieval(data: DataRetrieve):
	file = ""
	return { "storage": "success", "file": file }
