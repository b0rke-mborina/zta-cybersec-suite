from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum

from .utilityFunctions import sendRequest


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
	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8053/file/access-control",
		{
			"user_id": 1,
			"role": "user"
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)
	
	response = { "storage": "success" }
	storageResult = await sendRequest(
		"post",
		"http://127.0.0.1:8051/file/storage",
		{
			"user_id": 1,
			"format": data.format.value,
			"filename": data.filename,
			"file": data.file
		}
	)
	if storageResult[0].get("storage") != "success":
		raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8054/file/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response

@app.get("/file/retrieve")
async def retrieval(data: DataRetrieve):
	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8053/file/access-control",
		{
			"user_id": 1,
			"role": "user"
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)
	
	retrievalResult = await sendRequest(
		"get",
		"http://127.0.0.1:8051/file/retrieval",
		{
			"user_id": 1,
			"filename": data.filename
		}
	)
	file = retrievalResult[0].get("file")
	if retrievalResult[0].get("retrieval") != "success" and file is not None:
		raise HTTPException(500)
	response = { "storage": "success", "file": file }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8054/file/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
