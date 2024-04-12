from fastapi import FastAPI


app = FastAPI()


@app.post("/password/store")
async def storage():
	return {"status": "OK"}

@app.get("/password/retrieve")
async def retrieval():
	return {"status": "OK"}
