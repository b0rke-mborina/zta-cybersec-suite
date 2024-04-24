from fastapi import FastAPI


app = FastAPI()


@app.get("/data/retrieval")
def retrieval():
	return { "retrieval": "success" }
