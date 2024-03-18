from fastapi import FastAPI
from pydantic import BaseModel
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

@app.get("/cryptography/decrypt", status_code = 200)
async def decryption(data: Data):
	print(data)
	try:
		return { "decryption": "success", "plaintext": "HERE_GOES_PLAINTEXT" }
	except Exception as e:
		return { "decryption": "failure", "error": str(e) }
