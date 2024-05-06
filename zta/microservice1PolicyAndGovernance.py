from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from enum import Enum
from .utilityFunctions import handleProblem


app = FastAPI()


class Problem(str, Enum):
	SECURITY_BREACH = "security_breach"
	DOS_ATTACK = "dos_attack"
	DATA_INCONSISTENCY = "data_inconsistency"
	DATA_COMPROMISE = "data_compromise"
	INFRASTRUCTURE_INTEGRITY_VIOLATION = "infrastructure_integrity_violation"
	PARTIAL_SYSTEM_FAILURE = "partial_system_failure"
	TOTAL_SYSTEM_FAILURE = "total_system_failure"

class Data(BaseModel):
	problem: Problem
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "governance": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/zta/governance")
async def governance(data: Data):
	handleProblem(data.problem.value)
	return { "governance": "success" }
