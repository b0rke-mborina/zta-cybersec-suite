from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from .utilityFunctions import decryptFile, decryptSecret, encryptFile, encryptSecret, isStringValid, sendRequest


app = FastAPI()


class DataEncrypt(BaseModel):
	file: str

	@validator("file")
	def validateAndSanitizeString(cls, v):
		isValidTxt = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		isValidBase64 = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValidTxt and not isValidBase64:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataDecrypt(BaseModel):
	file: str
	key: str
	tag: str
	nonce: str

	@validator("file", "key", "tag", "nonce")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
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
		content = { "cryptography": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/file/encrypt")
async def encryption(data: DataEncrypt):
	(encryptedFile, key, tag, nonce) = encryptFile(data.file)
	
	encryptedKey = encryptSecret(key)
	encryptedTag = encryptSecret(tag)
	encryptedNonce = encryptSecret(nonce)

	return { "encryption": "success", "file": encryptedFile, "key": encryptedKey, "tag": encryptedTag, "nonce": encryptedNonce }

@app.get("/file/decrypt")
async def decryption(data: DataDecrypt):
	decryptedKey = decryptSecret(data.key)
	decryptedTag = decryptSecret(data.tag)
	decryptedNonce = decryptSecret(data.nonce)

	decryptedFile = decryptFile(data.file, decryptedKey, decryptedTag, decryptedNonce)

	return { "decryption": "success", "file": decryptedFile }
