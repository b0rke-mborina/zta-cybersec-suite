from fastapi import FastAPI


app = FastAPI()


@app.post("/hashing/reporting")
async def reporting():
	return {"status": "OK"}
