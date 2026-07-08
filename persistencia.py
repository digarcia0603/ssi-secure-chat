import json
import os

def carregar_json(caminho, valor_por_defeito, descricao="dados"):
    if not os.path.exists(caminho):
        return valor_por_defeito.copy() if hasattr(valor_por_defeito, "copy") else valor_por_defeito

    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Erro ao carregar {descricao}: {e}")
        return valor_por_defeito.copy() if hasattr(valor_por_defeito, "copy") else valor_por_defeito

def guardar_json(caminho, dados, descricao="dados", modo=0o600):
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=4)
        os.chmod(caminho, modo)
    except Exception as e:
        print(f"Erro ao guardar {descricao}: {e}")
