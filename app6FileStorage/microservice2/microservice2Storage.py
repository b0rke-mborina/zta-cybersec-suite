from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import asyncio
import os
from enum import Enum
from utilityFunctions import getFile, isStringValid, sendRequest, storeFile


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
		elif formatValue == "txt" and v == fileValue:
			regex = r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$'
		
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

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		os.getenv("URL_GOVERNANCE_MICROSERVICE"),
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
	tasks = [
		sendRequest(
			"get",
			os.getenv("URL_CRYPTOGRAPHY_MICROSERVICE_ENCRYPT"),
			{
				"file": data.file
			}
		),
		sendRequest(
			"get",
			os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
			{
				"data": {
					"filename": data.filename,
					"format": data.format,
				}
			}
		)
	]
	[cryptographyResult, orchestrationAutomationResult] = await asyncio.gather(*tasks)

	encryptedFile = cryptographyResult[0].get("file")
	key = cryptographyResult[0].get("key")
	tag = cryptographyResult[0].get("tag")
	nonce = cryptographyResult[0].get("nonce")
	filename = orchestrationAutomationResult[0].get("data").get("filename")
	fileFormat = orchestrationAutomationResult[0].get("data").get("format")

	if cryptographyResult[0].get("encryption") != "success" or any(value is None for value in [encryptedFile, key, tag, nonce]):
		raise HTTPException(500)
	if orchestrationAutomationResult[0].get("encryption") != "success" or any(value is None for value in [filename, fileFormat]):
		raise HTTPException(500)

	await storeFile("app6Data.db", data.user_id, filename, fileFormat, encryptedFile, key, tag, nonce)
	return { "storage": "success" }

@app.get("/file/retrieval")
async def retrieval(data: DataRetrieve):
	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"filename": data.filename
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	
	filename = orchestrationAutomationResult[0].get("data").get("filename")
	fileData = await getFile("app6Data.db", data.user_id, filename)

	decryptionResult = await sendRequest(
		"get",
		os.getenv("URL_CRYPTOGRAPHY_MICROSERVICE_DECRYPT"),
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
