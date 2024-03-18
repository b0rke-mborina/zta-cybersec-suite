import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, model_validator
import uvicorn
import aiohttp
import asyncio
from enum import Enum


app = FastAPI()

class Algorithm(str, Enum):
	TripleDES = "TripleDES"
	AES = "AES"
	RSA = "RSA"
	Blowfish = "Blowfish"
	Twofish = "Twofish"

class Data(BaseModel):
	algorithm: Algorithm
	plaintext: str
	key: str = None

@app.exception_handler(HTTPException)
async def service_2_exception_handler(request, exc):
	error_message = "Input invalid." if exc.status_code == 422 else exc.detail
	return {"detail": error_message}

async def request(session, data):
	async with session.get("http://127.0.0.1:8004/cryptography/logging", data = json.dumps(data)) as response:
		return await response.json()


async def task(reqData):
	async with aiohttp.ClientSession() as session:
		# tasks = [request(session) for i in range(100)]
		# result = await asyncio.gather(*tasks)
		task = request(session, reqData)
		result = await asyncio.gather(task)
		return result

@app.get("/cryptography/encrypt", status_code = 200)
async def encryption(data: Data):
	print("I AM AT ENCRYPTION MICROSERVICE")
	print(data)

	nesto={}
	nesto["timestamp"] = "2024-03-17"
	nesto["level"] = "INFO"
	nesto["logger_source"] = 1
	nesto["user_id"] = 1
	nesto["request"] = "something"
	nesto["error_message"] = "this is fine"

	result = await task(nesto)
	print("Res:")
	print(result)

	return { "message": "Request processed successfully", "data": result }
	"""try:
		return { "encryption": "success", "ciphertext": "HERE_GOES_CIPHERTEXT" }
	except Exception as e:
		return { "encryption": "failure", "error": str(e) }"""

# uvicorn app1Cryptography.microservice1Encryption:app --reload --host 127.0.0.1 --port 8001