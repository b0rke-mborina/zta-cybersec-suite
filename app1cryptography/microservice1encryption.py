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

@app.get("/cryptography/encrypt", status_code = 200)
def encryption(data: Data):
	print(data)
	try:
		return { "encryption": "success", "ciphertext": "HERE_GOES_CIPHERTEXT" }
	except Exception as e:
		return { "encryption": "failure", "error": str(e) }
