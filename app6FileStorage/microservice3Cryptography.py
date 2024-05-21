from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import decryptFile, encryptFile, sendRequest


app = FastAPI()


class DataEncrypt(BaseModel):
	file: str

class DataDecrypt(BaseModel):
	file: str
	key: str
	tag: str
	nonce: str

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
	(encryptedFile, key, tag, nonce) = await encryptFile(data.file)
	return { "encryption": "success", "file": encryptedFile, "key": key, "tag": tag, "nonce": nonce }

@app.get("/file/decrypt")
async def decryption(data: DataDecrypt):
	decryptedFile = await decryptFile(data.file, data.key, data.tag, data.nonce)
	return { "decryption": "success", "file": decryptedFile }
