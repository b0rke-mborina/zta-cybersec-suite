from fastapi import FastAPI


app = FastAPI()


@app.get("/password/logging")
async def logging():
	return {"status": "OK"}

