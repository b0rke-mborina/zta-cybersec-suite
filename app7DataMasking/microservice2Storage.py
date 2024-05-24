from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from .utilityFunctions import isStringValid, retrieveData, sendRequest, storeData


app = FastAPI()


class DataStorage(BaseModel):
	user_id: int
	dataset: str
	data_original: list
	data_masked: list

	@validator("dataset")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

	@validator("data_original", "data_masked")
	def validateAndSanitizeListStrings(cls, v):
		for l in v:
			for dataValue in l:
				if isinstance(dataValue, str):
					isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
					if not isValid:
						raise RequestValidationError("String is not valid.")
					return v

class DataRetrieval(BaseModel):
	user_id: int
	dataset: str

	@validator("dataset")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

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
