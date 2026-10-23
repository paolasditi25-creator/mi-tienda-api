# Para probar la API en tu compu (opcional):
#   pip install -r requirements-local.txt
#   python correr_local.py
# Luego abre http://localhost:8000  y  http://localhost:8000/docs
from dotenv import load_dotenv

load_dotenv()

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("api.index:app", host="0.0.0.0", port=8000, reload=True)
