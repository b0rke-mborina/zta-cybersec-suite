from fastapi import FastAPI


app = FastAPI()


@app.get("/file/logging")
async def logging():
	return {"status": "OK"}

