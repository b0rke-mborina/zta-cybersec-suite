from fastapi import FastAPI


app = FastAPI()


@app.post("/data/logging")
def logging():
	return { "logging": "success" }
