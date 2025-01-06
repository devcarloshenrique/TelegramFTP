from motor.motor_asyncio import AsyncIOMotorClient  # Cliente assíncrono do Motor para MongoDB
from asyncio import run  # Método run para executar funções assíncronas
from os import environ  # Função environ para acessar variáveis de ambiente
from os.path import exists  # Função exists para verificar a existência de arquivos

# Se o arquivo .env existir, carrega as variáveis de ambiente dele
if exists(".env"):
    # Importa a função load_dotenv para carregar variáveis de ambiente de um arquivo .env
    from dotenv import load_dotenv
    # Carrega as variáveis de ambiente do arquivo .env
    load_dotenv()

# Função assíncrona principal
async def main():
    # Conecta ao MongoDB usando a URL armazenada na variável de ambiente MONGODB
    mongo = AsyncIOMotorClient(environ.get("MONGODB")).ftp
    # Tenta criar as coleções 'users' e 'files' no banco de dados
    for collection in ["users", "files"]:
        try:
            # Tenta criar uma nova coleção no MongoDB
            await mongo.create_collection(collection)
        except Exception as e:
            print(f"Error: {e}")

# Se o script for executado diretamente, chama a função main
if __name__ == "__main__":
    # Executa a função main assíncrona de forma síncrona
    run(main())
