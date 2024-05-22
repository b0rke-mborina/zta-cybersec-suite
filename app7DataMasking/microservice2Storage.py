from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import retrieveData, sendRequest, storeData


app = FastAPI()


class DataStorage(BaseModel):
	user_id: int
	dataset: str
	data_original: list
	data_masked: list

class DataRetrieval(BaseModel):
	user_id: int
	dataset: str

@app.exception_handler(Exception)
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
		content = { "storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/data/store")
async def storage(data: DataStorage):
	await storeData("app7Data.db", data.user_id, data.dataset, data.data_original, data.data_masked)
	return { "storage": "success" }

@app.get("/data/retrieve")
async def retrieval(data: DataRetrieval):
	data = await retrieveData("app7Data.db", data.user_id, data.dataset)
	return { "retrieval": "success", "data": data }
