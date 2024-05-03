from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI()


@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "orchestration_automation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/orchestration")
async def orchestration():
	return { "orchestration": "success" }

@app.get("/zta/automation")
async def automation():
	return { "automation": "success" }
