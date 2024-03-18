from fastapi import FastAPI
from pydantic import BaseModel, model_validator
import json


app = FastAPI()


class DataGet(BaseModel):
	user_id: int
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data) # """"""

class DataStore(BaseModel):
	user_id: int
	key: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.get("/cryptography/key/get", status_code = 200)
async def getKey(data: DataGet):
	print(data)
	try:
		return { "key_retrieval": "success", "key": "HERE_GOES_KEY" }
	except Exception as e:
		return { "key_retrieval": "failure", "error": str(e) }

@app.post("/cryptography/key/store", status_code = 200)
async def storeKey(data: DataStore):
	print(data)
	try:
		return { "key_storage": "success" }
	except Exception as e:
		return { "key_storage": "failure", "error": str(e) }
