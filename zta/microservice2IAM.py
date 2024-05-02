from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/iam")
async def identityAndAccessManagement():
	return { "iam": "success" }
