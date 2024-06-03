from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
from enum import Enum
from .utilityFunctions import getFile, isStringValid, sendRequest, storeFile


app = FastAPI()


class Format(str, Enum):
	TXT = "txt"
	BASE64 = "base64"

class DataStore(BaseModel):
	user_id: str
	format: Format
	filename: str
	file: str

	class Config:
		use_enum_values = True

	@field_validator("user_id")
	def validateAndSanitizeString(cls, v, info):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

	@validator("filename", "file", always = True)
	def validateAndSanitizeString(cls, v, values):
		formatValue = values.get("format")
		fileValue = values.get("file")

		regex = r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$'
		if formatValue == "base64" and v == fileValue:
			regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
		
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataRetrieve(BaseModel):
	user_id: str
	filename: str

	@field_validator("user_id")
	def validateAndSanitizeString(cls, v, info):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

	@validator("filename")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(HTTPException)
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

	await storeFile("app6Data.db", data.user_id, data.filename, data.format, encryptedFile, key, tag, nonce)
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
