from fastapi import FastAPI

app = FastAPI()


@app.get("/cryptography/logging")
def logging():
	return {"logging": "OK"}
