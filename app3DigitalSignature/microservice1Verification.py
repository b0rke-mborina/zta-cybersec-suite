from fastapi import FastAPI
from pydantic import BaseModel
from enum import Enum


app = FastAPI()


class HashFunction(str, Enum):
	SHA256 = "sha256"
	SHA512 = "sha512"

class Data(BaseModel):
	public_key: str
	digital_signature: str
	message: str
	hash_function: HashFunction

@app.get("/digital-signature/verify")
async def digitalSignatureVerificator(data: Data):
	print(data)
	return {"status": "OK"}

