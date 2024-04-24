from fastapi import FastAPI


app = FastAPI()


@app.post("/data/store")
def storage():
	return { "storage": "success" }

@app.get("/data/retrieve")
def retrieval():
	return { "retrieval": "success" }
