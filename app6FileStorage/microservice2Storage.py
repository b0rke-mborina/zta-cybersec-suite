from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from enum import Enum
from .utilityFunctions import getFile, sendRequest, storeFile


app = FastAPI()


class Format(str, Enum):
	TXT = "txt"
	BASE64 = "base64"

class DataStore(BaseModel):
	user_id: int
	format: Format
	filename: str
	file: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

class DataRetrieve(BaseModel):
	user_id: int
	filename: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/file/storage")
async def storage(data: DataStore):
	encryptionResult = await sendRequest(
		"get",
		"http://127.0.0.1:8052/file/encrypt",
		{
			"file": data.file
		}
	)
	encryptedFile = encryptionResult[0].get("file")
	key = encryptionResult[0].get("key")
	tag = encryptionResult[0].get("tag")
	nonce = encryptionResult[0].get("nonce")
	if encryptionResult[0].get("encryption") != "success" or any(value is None for value in [encryptedFile, key, tag, nonce]):
		raise HTTPException(500)

	await storeFile("app6Data.db", data.user_id, data.filename, data.format.value, encryptedFile, key, tag, nonce)
	return { "storage": "success" }

@app.get("/file/retrieval")
async def retrieval(data: DataRetrieve):
	fileData = await getFile("app6Data.db", data.user_id, data.filename)

	decryptionResult = await sendRequest(
		"get",
		"http://127.0.0.1:8052/file/decrypt",
		{
			"file": fileData[0][3],
			"key": fileData[0][4],
			"tag": fileData[0][5],
			"nonce": fileData[0][6]
		}
	)
	decryptedFile = decryptionResult[0].get("file")
	print(decryptionResult)
	if decryptionResult[0].get("decryption") != "success" or decryptedFile is None:
		raise HTTPException(500)

	return { "retrieval": "success", "file": decryptedFile }
