from fastapi import FastAPI


app = FastAPI()


@app.get("/data/access-control")
def accessControl():
	return { "access_control": "success" }
