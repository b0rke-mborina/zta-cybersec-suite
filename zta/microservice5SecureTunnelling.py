from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/tunnelling")
async def tunnelling():
	return { "tunnelling": "success" }
