from fastapi import FastAPI


app = FastAPI()


@app.post("/data/store")
async def storage():
	return { "storage": "success" }

@app.get("/data/retrieve")
async def retrieval():
	return { "retrieval": "success" }
