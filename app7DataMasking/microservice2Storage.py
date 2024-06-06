from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import json
from .utilityFunctions import decryptBlowfish, encryptBlowfish, isStringValid, retrieveData, sendRequest, storeData


app = FastAPI()


class DataStorage(BaseModel):
	user_id: str
	dataset: str
	data_original: list
	data_masked: list

	@validator("user_id")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

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
					isValid = isStringValid(dataValue, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
					if not isValid:
						raise RequestValidationError("String is not valid.")
		return v

class DataRetrieval(BaseModel):
	user_id: str
	dataset: str

	@validator("user_id")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

	@validator("dataset")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	print(exc)
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
	dataset = encryptBlowfish("dataset", data.dataset)
	dataOriginal = encryptBlowfish("data_original", json.dumps(data.data_original))
	dataMasked = encryptBlowfish("data_masked", json.dumps(data.data_masked))

	await storeData("app7Data.db", data.user_id, dataset, dataOriginal, dataMasked)

	return { "storage": "success" }

@app.get("/data/retrieve")
async def retrieval(data: DataRetrieval):
	dataset = encryptBlowfish("dataset", data.dataset)
	encrypedData = await retrieveData("app7Data.db", data.user_id, dataset)

	decryptedData = decryptBlowfish("data_original", encrypedData)
	data = json.loads(decryptedData)

	return { "retrieval": "success", "data": data }
