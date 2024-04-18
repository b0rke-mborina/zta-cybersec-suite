from fastapi import FastAPI


app = FastAPI()


@app.get("/file/storage")
async def storage():
	return {"status": "OK"}

@app.get("/file/retrieval")
async def retrieval():
	return {"status": "OK"}
