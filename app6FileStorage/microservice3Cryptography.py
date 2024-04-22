from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import decryptFile, encryptFile


app = FastAPI()


class Data(BaseModel):
	file: str

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "cryptography": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/file/encrypt")
async def encryption(data: Data):
	(encryptedFile, key, tag, nonce) = await encryptFile(data.file)
	return { "encryption": "success", "file": encryptedFile } # , "key": key, "tag": tag, "nonce": nonce

@app.get("/file/decrypt")
async def decryption(data: Data):
	decryptedFile = await decryptFile(data.file)
	return { "decryption": "success", "file": decryptedFile }
