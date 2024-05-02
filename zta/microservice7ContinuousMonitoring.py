from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/monitoring")
async def identityAndAccessManagement():
	return { "monitoring": "success" }
