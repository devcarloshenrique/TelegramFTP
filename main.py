import asyncio  # Biblioteca para programação assíncrona e gerenciamento de eventos.
from ftp import Server, MongoDBUserManager, MongoDBPathIO  # Importa classes necessárias para o servidor FTP.
from os import environ  # Permite acesso às variáveis de ambiente.
from os.path import exists  # Verifica se um arquivo ou diretório existe.
from pyrogram import Client  # Biblioteca para criar bots e clientes Telegram.
from motor.motor_asyncio import AsyncIOMotorClient  # Cliente assíncrono para MongoDB.

# Carrega variáveis de ambiente a partir de um arquivo .env, se ele existir.
if exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()

async def main():
    # Configura e inicializa o bot do Telegram.
    bot = Client(
        "FTP_Bot",
        api_id=int(environ.get("API_ID", 0)),  # Obtém o ID da API do Telegram a partir das variáveis de ambiente.
        api_hash=environ.get("API_HASH"),  # Obtém o hash da API do Telegram.
        bot_token=environ.get("BOT_TOKEN"),  # Obtém o token do bot do Telegram.
        in_memory=True  # Armazena sessões em memória, útil para evitar arquivos temporários.
    )
    await bot.start()  # Inicia o bot do Telegram.

    # Obtém o loop de eventos assíncronos.
    loop = asyncio.get_event_loop()

    # Conecta ao MongoDB e seleciona a base de dados "ftp".
    mongo = AsyncIOMotorClient(environ.get("MONGODB"), io_loop=loop).ftp

    # Configura o gerenciador de arquivos MongoDBPathIO.
    MongoDBPathIO.db = mongo  # Define a base de dados MongoDB para armazenar arquivos.
    MongoDBPathIO.tg = bot  # Define o bot do Telegram para interagir com arquivos.
    MongoDBPathIO.chunk_size = 1024 * 1024 * 16  # Define o tamanho do chunk (16 MB), para evitar FloodWait no Telegram.
    MongoDBPathIO.download_workers = 2  # Define o número de workers para download simultâneo, ajudando a evitar erros de FloodWait.

    # Configura o servidor FTP com autenticação baseada no MongoDB.
    server = Server(MongoDBUserManager(mongo), MongoDBPathIO)

    print("FTP server starting...")  # Mensagem de inicialização do servidor.

    # Inicia o servidor FTP, escutando no host e porta definidos nas variáveis de ambiente.
    await server.run(environ.get("HOST", "0.0.0.0"), int(environ.get("PORT", 9021)))

# Executa a função assíncrona principal.
asyncio.run(main())
