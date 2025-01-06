from pyrogram import Client, filters  # Importa a classe Client para criar o bot e o filtro de mensagens
from os import environ  # Função environ para acessar variáveis de ambiente
from os.path import exists  # Função exists para verificar a existência de arquivos

if exists(".env"):  # Verifica se o arquivo .env existe
    from dotenv import load_dotenv  # Função load_dotenv para carregar variáveis de ambiente de um arquivo .env
    load_dotenv()  # Carrega as variáveis de ambiente do arquivo .env

# Cria o bot com as credenciais fornecidas pelas variáveis de ambiente
bot = Client(
    "S3_Bot",  # Nome do bot
    api_id=int(environ.get("API_ID", 0)),  # ID da API do Telegram
    api_hash=environ.get("API_HASH"),  # Hash da API do Telegram
    bot_token=environ.get("BOT_TOKEN")  # Token do bot
)

# Define o que o bot faz quando recebe uma mensagem de texto
@bot.on_message(filters.text)  # Aciona quando uma mensagem de texto é recebida
async def get_id(_cl, message):
    if message.text.startswith("/id") or message.text.startswith("/channel"):  # Verifica se a mensagem começa com '/id' ou '/channel'
        await message.reply(str(message.chat.id))  # Responde com o ID do chat
    
    print(message)

if __name__ == "__main__":  # Verifica se o script é executado diretamente
    try:
        print('Press Ctrl+C to stop.')  # Informa que o bot está rodando e pode ser parado com Ctrl+C
        bot.run()  # Inicia o bot
    except KeyboardInterrupt:  # Captura a interrupção pelo Ctrl+C
        exit()  # Finaliza a execução
        pass  # Passa para a próxima instrução (não necessária aqui)
