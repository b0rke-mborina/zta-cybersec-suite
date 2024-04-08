from fastapi import FastAPI


app = FastAPI()


@app.get("/hashing/check")
async def dataIntegrityChecker():
	return {"status": "OK"}
