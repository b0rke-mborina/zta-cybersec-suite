from fastapi import FastAPI


app = FastAPI()


@app.get("/password/verify")
async def verification():
	return {"status": "OK"}

