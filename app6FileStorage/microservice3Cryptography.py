from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import decryptFile, encryptFile


app = FastAPI()


class DataEncrypt(BaseModel):
	file: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

class DataDecrypt(BaseModel):
	file: str
	key: str
	tag: str
	nonce: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "cryptography": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/file/encrypt")
async def encryption(data: DataEncrypt):
	(encryptedFile, key, tag, nonce) = await encryptFile(data.file)
	return { "encryption": "success", "file": encryptedFile, "key": key, "tag": tag, "nonce": nonce }

@app.get("/file/decrypt")
async def decryption(data: DataDecrypt):
	decryptedFile = await decryptFile(data.file, data.key, data.tag, data.nonce)
	return { "decryption": "success", "file": decryptedFile }
