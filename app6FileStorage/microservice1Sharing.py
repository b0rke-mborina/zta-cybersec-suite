from fastapi import FastAPI


app = FastAPI()


@app.get("/file/store")
async def storage():
	return {"status": "OK"}

@app.get("/file/retrieve")
async def retrieval():
	return {"status": "OK"}
