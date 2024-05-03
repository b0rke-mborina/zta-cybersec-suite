from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI()


@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "tunnelling": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/tunnelling")
async def tunnelling():
	return { "tunnelling": "success" }
