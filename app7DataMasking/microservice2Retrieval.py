from fastapi import FastAPI


app = FastAPI()


@app.get("/data/retrieval")
async def retrieval():
	return { "retrieval": "success" }
