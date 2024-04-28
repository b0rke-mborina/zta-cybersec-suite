from fastapi import FastAPI


app = FastAPI()


@app.post("/intelligence/report")
async def reporting():
	return { "reporting": "success" }

@app.get("/intelligence/retrieve")
async def retrieval():
	return { "retrieval": "success" }
