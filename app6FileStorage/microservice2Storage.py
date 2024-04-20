from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from enum import Enum
from .utilityFunctions import getFile, storeFile


app = FastAPI()


class Format(str, Enum):
	TXT = "txt"
	BASE64 = "base64"

class DataStore(BaseModel):
	user_id: int
	format: Format
	filename: str
	file: str

class DataRetrieve(BaseModel):
	user_id: int
	filename: str

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/file/storage")
async def storage(data: DataStore):
	await storeFile(data.user_id, data.format, data.filename, data.file)
	return { "storage": "success" }

@app.get("/file/retrieval")
async def retrieval(data: DataRetrieve):
	file = await getFile(data.user_id, data.filename)
	return { "storage": "success", "file": file }
