from fastapi import FastAPI


app = FastAPI()


@app.get("/data/mask")
def masking():
	return { "masking": "success" }

@app.get("/data/unmask")
def unmasking():
	return { "unmasking": "success" }
