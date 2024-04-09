from fastapi import FastAPI
from pydantic import BaseModel
from enum import Enum
from .utilityFunctions import verifyChecksum


app = FastAPI()


class Algorithm(str, Enum):
	MD5 = "MD5"
	SHA1 = "SHA-1"
	SHA256 = "SHA-256"
	SHA512 = "SHA-512"

class Data(BaseModel):
	data: str
	algorithm: Algorithm
	checksum: str

@app.get("/hashing/verify", status_code = 200)
async def verification(data: Data):
	isHashValid = verifyChecksum(data.data, data.algorithm.value, data.checksum)
	return { "hashing": "success", "is_checksum_valid": 1 if isHashValid else 0 }
