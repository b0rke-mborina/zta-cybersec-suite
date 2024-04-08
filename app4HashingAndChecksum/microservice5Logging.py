from fastapi import FastAPI


app = FastAPI()


@app.post("/hashing/logging")
async def logging():
	return {"status": "OK"}
