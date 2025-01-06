"""ftp client/server for asyncio"""
# flake8: noqa
# O comentário acima desativa verificações do flake8 (ferramenta de linting) para este arquivo.

from .common import *  # Importa todos os itens do módulo common
from .errors import *  # Importa todos os itens do módulo errors
from .pathio import *  # Importa todos os itens do módulo pathio
from .server import *  # Importa todos os itens do módulo server

__version__ = "0.21.2"  # Define a versão atual do pacote como uma string
version = tuple(map(int, __version__.split(".")))
# Converte a versão em string para uma tupla de inteiros. Por exemplo, "0.21.2" se torna (0, 21, 2).

__all__ = (
    server.__all__ +
    errors.__all__ +
    common.__all__ +
    pathio.__all__ +
    ("version", "__version__")
)
# Define os itens que serão exportados quando `from <module> import *` for usado.
# Ele combina os elementos de __all__ de cada módulo importado e adiciona "version" e "__version__".
