from fastapi import FastAPI
from pydantic import BaseModel
from enum import Enum
from .utilityFunctions import hashData


app = FastAPI()


class Algorithm(str, Enum):
	MD5 = "MD5"
	SHA1 = "SHA-1"
	SHA256 = "SHA-256"
	SHA512 = "SHA-512"

class Data(BaseModel):
	data: str
	algorithm: Algorithm

@app.get("/hashing/hash", status_code = 200)
async def hashing(data: Data):
	hash = hashData(data.data, data.algorithm.value)
	return { "hashing": "success", "hash": hash }
