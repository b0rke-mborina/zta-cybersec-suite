from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import retrieveData, storeData


app = FastAPI()


class DataStorage(BaseModel):
	dataset: str
	data_original: list
	data_masked: list

class DataRetrieval(BaseModel):
	dataset: str

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/data/store")
async def storage(data: DataStorage):
	await storeData("app7Data.db", 1, data.dataset, data.data_original, data.data_masked)
	return { "storage": "success" }

@app.get("/data/retrieve")
async def retrieval(data: DataRetrieval):
	data = await retrieveData("app7Data.db", 1, data.dataset)
	return { "retrieval": "success", "data": data }
