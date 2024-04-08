from fastapi import FastAPI


app = FastAPI()


@app.get("/hashing/verify")
async def verification():
	return {"status": "OK"}
