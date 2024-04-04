from fastapi import FastAPI


app = FastAPI()


@app.get("/digital-signature/logging")
async def logging():
	return {"status": "OK"}

