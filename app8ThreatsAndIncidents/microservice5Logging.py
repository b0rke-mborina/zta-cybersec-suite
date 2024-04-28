from fastapi import FastAPI


app = FastAPI()


@app.post("/intelligence/logging")
async def logging():
	return { "logging": "success" }
