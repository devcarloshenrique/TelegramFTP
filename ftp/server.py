from asyncio import Future, wait_for, gather, TimeoutError, shield, CancelledError, start_server, create_task, wait, Queue, current_task, get_running_loop, FIRST_COMPLETED  
# Ferramentas para manipulação de tarefas e operações assíncronas:
# Future: Representa o resultado de uma operação assíncrona.
# wait_for: Espera uma operação assíncrona com limite de tempo.
# gather: Executa múltiplas tarefas assíncronas simultaneamente.
# TimeoutError: Exceção para tempo limite excedido.
# shield: Protege tarefas de serem canceladas.
# CancelledError: Exceção para tarefas canceladas.
# start_server: Inicia um servidor assíncrono.
# create_task: Cria uma nova tarefa assíncrona.
# wait: Aguarda múltiplas tarefas serem concluídas.
# Queue: Implementa filas assíncronas.
# current_task: Obtém a tarefa atual em execução.
# get_running_loop: Obtém o loop de eventos ativo.
# FIRST_COMPLETED: Espera até que a primeira tarefa seja concluída.

from collections import defaultdict  # Cria dicionários com valores padrão para chaves inexistentes.

from enum import Enum  # Define conjuntos de constantes nomeadas.

from functools import wraps, partial  
# wraps: Preserva metadados de funções decoradas.
# partial: Cria funções parcialmente aplicadas (com argumentos fixos).

from pathlib import PurePosixPath, Path  
# PurePosixPath: Representa caminhos no estilo POSIX.
# Path: Classe de alto nível para manipular caminhos de arquivos.

from socket import AF_INET, AF_INET6  
# AF_INET: Família de endereços para IPv4.
# AF_INET6: Família de endereços para IPv6.

from stat import filemode  # Converte permissões de arquivos em formato legível.

from time import strftime, gmtime, time, localtime  
# strftime: Formata a data/hora como string.
# gmtime: Converte timestamp para UTC.
# time: Retorna o timestamp atual.
# localtime: Converte timestamp para o horário local.

from chardet import detect as cdetect  # Detecta a codificação de texto (usado para identificar encoding de arquivos).

from .errors import PathIOError, NoAvailablePort  
# PathIOError: Exceção para erros relacionados a operações de entrada/saída.
# NoAvailablePort: Exceção quando nenhuma porta está disponível.

from .pathio import PathIONursery  # Gerencia operações de entrada e saída de arquivos.

from .common import StreamIO, setlocale, wrap_with_container  
# StreamIO: Gerencia fluxos de entrada e saída.
# setlocale: Configura a localidade do sistema.
# wrap_with_container: Envolve dados em um contêiner específico.

__all__ = (
    "Permission",              # Representa permissões de acesso.
    "User",                    # Classe que define um usuário.
    "AbstractUserManager",     # Classe base para gerenciar usuários.
    "MongoDBUserManager",      # Implementação de gerenciador de usuários usando MongoDB.
    "Connection",              # Representa uma conexão.
    "AvailableConnections",    # Gerencia conexões disponíveis.
    "ConnectionConditions",    # Define condições específicas para conexões.
    "PathConditions",          # Define condições relacionadas a caminhos.
    "PathPermissions",         # Gerencia permissões para caminhos.
    "worker",                  # Representa uma unidade de trabalho (e.g., tarefa assíncrona).
    "Server",                  # Classe que implementa o servidor FTP.
)


class Permission:  
    # Classe que representa permissões de acesso para um caminho específico.

    def __init__(self, path="/", *, readable=False, writable=False):  
        # Inicializa a permissão com um caminho base e permissões de leitura e escrita.
        self.path = PurePosixPath(path)  
        # Converte o caminho fornecido para o formato POSIX padrão.
        self.readable = readable or writable  
        # Permite leitura se a permissão de gravação for ativada.
        self.writable = writable  
        # Define se o caminho é gravável.

    def is_parent(self, other):  
        # Verifica se o caminho atual é pai de outro caminho.
        try:  
            other.relative_to(self.path)  
            # Retorna True se 'other' for um subcaminho de 'self.path'.
            return True  
        except ValueError:  
            # Retorna False se 'other' não for relativo a 'self.path'.
            return False  

class User:  
    # Classe que representa um usuário com login, senha e permissões de acesso.

    def __init__(self, login, password, permissions=[]):  
        # Inicializa um usuário com login, senha e uma lista de permissões.
        self.login = login  
        # Define o login do usuário.
        self.password = password  
        # Define a senha do usuário.
        self.base_path = Path(".")  
        # Define o caminho base padrão como o diretório atual.
        self.home_path = PurePosixPath(f"/{login}")  
        # Define o caminho home do usuário baseado no login.
        self.permissions = [Permission(f"/{login}", readable=True, writable=True)]  
        # Adiciona permissões padrão (leitura e escrita) para o caminho home.
        self.permissions += permissions  
        # Adiciona permissões adicionais, se fornecidas.
        if not [p for p in self.permissions if p.path == PurePosixPath("/")]:  
            # Se não houver permissões para a raiz "/", adiciona uma restritiva (sem leitura ou escrita).
            self.permissions.append(Permission("/", readable=False, writable=False))  

    def get_permissions(self, path):  
        # Obtém as permissões mais específicas para um caminho.
        path = PurePosixPath(path)  
        # Converte o caminho fornecido para o formato POSIX.
        parents = filter(lambda p: p.is_parent(path), self.permissions)  
        # Filtra as permissões cujos caminhos são pais do caminho fornecido.
        perm = min(parents, key=lambda p: len(path.relative_to(p.path).parts), default=Permission())  
        # Seleciona a permissão mais específica com base na proximidade do caminho.
        return perm  

    def update(self, d):  
        # Atualiza a senha e permissões do usuário com base em um objeto fornecido.
        self.password = d.password or self.password  
        # Atualiza a senha, se fornecida.
        self.permissions.clear()  
        # Limpa todas as permissões existentes.
        self.permissions = [Permission(f"/{self.login}", readable=True, writable=True)]  
        # Redefine permissões padrão para o caminho home.
        for perm in d.permissions:  
            # Adiciona permissões fornecidas.
            self.permissions.append(perm)  
        return self  

    @classmethod  
    def from_dict(cls, d):  
        # Cria uma instância de User a partir de um dicionário.
        login = d["login"]  
        # Extrai o login do dicionário.
        permissions = []  
        # Inicializa a lista de permissões.
        for perm in d.get("permissions", []):  
            # Itera sobre as permissões fornecidas.
            if perm["path"] != f"/{login}":  
                # Ajusta o caminho se não corresponder ao caminho home.
                perm["path"] = perm["path"].strip()  
                # Remove espaços em branco do caminho.
                permissions.append(Permission(**perm))  
                # Adiciona a permissão formatada à lista.
        return cls(login, d["password"], permissions)  
        # Retorna uma nova instância de User com as permissões processadas.

class AbstractUserManager:  
    # Classe base para o gerenciamento de usuários, contém respostas para o processo de autenticação.
    GetUserResponse = Enum("UserManagerResponse", "PASSWORD_REQUIRED ERROR")  
    # Enum que define os tipos de resposta para o gerenciamento de usuários: 'PASSWORD_REQUIRED' ou 'ERROR'.

class MongoDBUserManager(AbstractUserManager):  
    # Gerenciador de usuários que se conecta ao banco de dados MongoDB.
    
    def __init__(self, db):  
        # Inicializa com o banco de dados MongoDB e configura as variáveis de estado.
        self.db = db  
        # Define o banco de dados utilizado.
        self.available_connections = {}  
        # Armazena o número de conexões disponíveis para cada usuário.
        self.users = []  
        # Armazena os usuários carregados.

    async def get_user(self, login):  
        # Recupera um usuário a partir do banco de dados e verifica as permissões de conexão.
        user = User.from_dict(await self.db.users.find_one({"login": login}))  
        # Busca o usuário no banco de dados MongoDB.
        if user:  
            u = [usr for usr in self.users if usr.login == user.login]  
            # Verifica se o usuário já está na lista local de usuários.
            if u:  
                user = u[0].update(user)  
                # Atualiza o usuário local se ele já existir.
            else:  
                self.users.append(user)  
                # Adiciona o usuário na lista local se for novo.
            if user.login not in self.available_connections:  
                # Verifica se o usuário já tem conexões disponíveis.
                self.available_connections[user] = AvailableConnections(4)  
                # Se não, define 4 conexões disponíveis para o usuário.
        if not user:  
            state = AbstractUserManager.GetUserResponse.ERROR  
            # Se o usuário não for encontrado, define o estado como 'ERROR'.
            info = "no such username"  
            # Mensagem de erro informando que o nome de usuário não foi encontrado.
        elif self.available_connections[user].locked():  
            state = AbstractUserManager.GetUserResponse.ERROR  
            # Se o número máximo de conexões foi atingido, define o estado como 'ERROR'.
            info = f"too much connections for {user.login!r}"  
            # Mensagem de erro indicando que o número de conexões do usuário excedeu o limite.
        else:  
            state = AbstractUserManager.GetUserResponse.PASSWORD_REQUIRED  
            # Se o usuário foi encontrado e não atingiu o limite de conexões, solicita a senha.
            info = "password required"  

        if state != AbstractUserManager.GetUserResponse.ERROR:  
            self.available_connections[user].acquire()  
            # Se não houve erro, aumenta o número de conexões para o usuário.

        return state, user, info  
        # Retorna o estado, o usuário e informações sobre o processo de autenticação.

    async def authenticate(self, user, password):  
        # Método que autentica o usuário comparando a senha fornecida.
        return user.password == password  # Retorna True se a senha for correta.

    async def notify_logout(self, user):  
        # Notifica quando um usuário faz logout, liberando uma conexão.
        self.available_connections[user].release()  
        # Libera uma conexão para o usuário.
        
class Connection(defaultdict):  
    # Representa uma conexão, extendendo defaultdict para armazenar resultados de futuras chamadas.
    
    __slots__ = ("future",)  
    # Define os atributos permitidos para a classe, limitando o uso de memória.

    class Container:  
        # Classe interna para gerenciar o armazenamento de atributos.
        def __init__(self, storage):  
            self.storage = storage  # Inicializa com o armazenamento fornecido.

        def __getattr__(self, name):  
            return self.storage[name]  # Retorna o valor armazenado.

        def __delattr__(self, name):  
            self.storage.pop(name)  # Deleta o valor armazenado.

    def __init__(self, **kwargs):  
        # Inicializa a conexão com os parâmetros fornecidos.
        super().__init__(Future)  
        # Usa o defaultdict com o tipo de valor Future.
        self.future = Connection.Container(self)  
        # Cria um contêiner para armazenar os resultados das futuras chamadas.
        for k, v in kwargs.items():  
            self[k].set_result(v)  # Define o valor do Future imediatamente.

    def __getattr__(self, name):  
        # Sobrescreve o método __getattr__ para acessar o valor da Future.
        if name in self:  
            return self[name].result()  # Retorna o resultado se estiver concluído.
        else:  
            raise AttributeError(f"{name!r} not in storage")  
            # Levanta um erro se o atributo não existir.

    def __setattr__(self, name, value):  
        # Sobrescreve o método __setattr__ para modificar valores armazenados.
        if name in Connection.__slots__:  
            super().__setattr__(name, value)  # Modifica atributos em __slots__.
        else:  
            if self[name].done():  
                self[name] = super().default_factory()  # Reinicia o valor se a Future estiver concluída.
            self[name].set_result(value)  # Define o resultado da Future.

    def __delattr__(self, name):  
        # Sobrescreve o método __delattr__ para deletar atributos armazenados.
        if name in self:  
            self.pop(name)  # Remove o atributo do armazenamento.

class AvailableConnections:
    # Classe que gerencia o número de conexões disponíveis.

    def __init__(self, value=None):
        # Inicializa o objeto com o valor de conexões disponíveis.
        self.value = self.maximum_value = value  # 'value' é o número inicial de conexões.

    def locked(self):
        # Verifica se não há conexões disponíveis.
        return self.value == 0  # Retorna True se não houver conexões restantes, caso contrário, False.

    def acquire(self):
        # Diminui o número de conexões disponíveis quando uma conexão é adquirida.
        if self.value is not None:
            self.value -= 1  # Diminui uma unidade de 'value'.
            if self.value < 0:  # Se o valor for menor que zero, significa que há mais aquisições do que o permitido.
                raise ValueError("Too many acquires")  # Lança erro.

    def release(self):
        # Aumenta o número de conexões disponíveis quando uma conexão é liberada.
        if self.value is not None:
            self.value += 1  # Aumenta o valor de 'value'.
            if self.value > self.maximum_value:  # Se o valor de 'value' for maior que o máximo permitido, lança erro.
                raise ValueError("Too many releases")  # Lança erro.

class ConnectionConditions:
    # Definindo as condições que devem ser verificadas em relação à conexão.

    user_required = ("user", "no user (use USER firstly)")  # Condição: o usuário deve estar presente.
    login_required = ("logged", "not logged in")  # Condição: o usuário deve estar logado.
    passive_server_started = ("passive_server", "no listen socket created (use PASV firstly)")  # Condição: o servidor passivo deve estar iniciado.
    data_connection_made = ("data_connection", "no data connection made")  # Condição: uma conexão de dados deve ter sido estabelecida.
    rename_from_required = ("rename_from", "no filename (use RNFR firstly)")  # Condição: um nome de arquivo de origem deve ser fornecido.

    def __init__(self, *fields, wait=False, fail_code="503", fail_info=None):
        # Inicializa as condições com os parâmetros passados.
        self.fields = fields  # Armazena os campos que devem ser verificados.
        self.wait = wait  # Determina se o sistema deve esperar para verificar as condições.
        self.fail_code = fail_code  # Código de falha a ser retornado se as condições não forem atendidas.
        self.fail_info = fail_info  # Mensagem adicional a ser retornada caso haja falha nas condições.

    def __call__(self, f):
        # Torna a classe utilizável como um decorador para funções.
        @wraps(f)
        async def wrapper(cls, connection, rest, *args):
            # Cria um dicionário de futuras verificações baseadas nos campos passados para a classe.
            futures = {connection[name]: msg for name, msg in self.fields}
            aggregate = gather(*futures)  # Junta as futuras verificações em uma operação assíncrona.
            
            # Define o tempo limite baseado na opção 'wait'.
            if self.wait:
                timeout = 1  # Tempo de espera definido para 1 segundo se 'wait' for True.
            else:
                timeout = 0  # Caso contrário, o tempo de espera é 0 (sem esperar).

            try:
                # Aguarda a execução de todas as verificações de condições.
                await wait_for(shield(aggregate), timeout)
            except TimeoutError:
                # Caso o tempo de espera seja excedido, retorna uma resposta de erro para cada condição não atendida.
                for future, message in futures.items():
                    if not future.done():
                        # Se não estiver concluído, retorna uma resposta de falha.
                        if self.fail_info is None:
                            info = f"bad sequence of commands ({message})"  # Mensagem padrão de erro.
                        else:
                            info = self.fail_info  # Se houver uma mensagem personalizada, usa-a.
                        connection.response(self.fail_code, info)  # Retorna o código de falha e a mensagem.
                        return True
            # Caso as condições sejam atendidas, chama a função original.
            return await f(cls, connection, rest, *args)

        return wrapper  # Retorna o wrapper que aplica as condições à função original.

class PathConditions:
    # Define várias condições relacionadas ao caminho (path).
    path_must_exists = ("exists", False, "path does not exists")  # O caminho deve existir, se não existir, exibe a mensagem.
    path_must_not_exists = ("exists", True, "path already exists")  # O caminho não deve existir, se já existir, exibe a mensagem.
    path_must_be_dir = ("is_dir", False, "path is not a directory")  # O caminho deve ser um diretório, se não for, exibe a mensagem.
    path_must_be_file = ("is_file", False, "path is not a file")  # O caminho deve ser um arquivo, se não for, exibe a mensagem.

    def __init__(self, *conditions):
        # Inicializa a classe com as condições passadas como parâmetros.
        self.conditions = conditions  # Armazena as condições passadas.

    def __call__(self, f):
        # Torna a classe utilizável como um decorador para as funções.
        @wraps(f)
        async def wrapper(cls, connection, rest, *args):
            # Obtém os caminhos real e virtual para verificação das condições.
            real_path, virtual_path = cls.get_paths(connection, rest)
            
            # Itera sobre todas as condições e as verifica.
            for name, fail, message in self.conditions:
                # Obtém o método que será chamado na verificação da condição.
                coro = getattr(connection.path_io, name)
                
                # Se a condição não for atendida (resultado diferente de 'fail'), retorna a resposta de erro.
                if await coro(real_path) == fail:
                    connection.response("550", message)  # Responde com erro 550 e a mensagem especificada.
                    return True  # Interrompe a execução, pois a condição falhou.

            # Se todas as condições forem atendidas, chama a função original.
            return await f(cls, connection, rest, *args)

        return wrapper  # Retorna o wrapper que aplica as condições.

class PathPermissions:
    # Define permissões de leitura e escrita para os caminhos.
    readable = "readable"  # Permissão para leitura.
    writable = "writable"  # Permissão para escrita.

    def __init__(self, *permissions):
        # Inicializa a classe com as permissões passadas como parâmetros.
        self.permissions = permissions  # Armazena as permissões passadas.

    def __call__(self, f):
        # Torna a classe utilizável como um decorador para as funções.
        @wraps(f)
        async def wrapper(cls, connection, rest, *args):
            # Obtém os caminhos real e virtual para verificação das permissões.
            real_path, virtual_path = cls.get_paths(connection, rest)
            
            # Obtém as permissões atuais do usuário para o caminho virtual.
            current_permission = connection.user.get_permissions(virtual_path)
            
            # Itera sobre todas as permissões solicitadas e verifica se o usuário tem permissão.
            for permission in self.permissions:
                # Verifica se a permissão não está presente. Se não tiver permissão, retorna um erro.
                if not getattr(current_permission, permission):
                    connection.response("550", "permission denied")  # Responde com erro 550 e a mensagem de permissão negada.
                    return True  # Interrompe a execução, pois a permissão não foi concedida.
            
            # Se todas as permissões forem atendidas, chama a função original.
            return await f(cls, connection, rest, *args)

        return wrapper  # Retorna o wrapper que aplica as permissões.

def worker(f):
    @wraps(f)
    async def wrapper(cls, connection, rest):
        try:
            await f(cls, connection, rest)
        except CancelledError:
            connection.response("426", "transfer aborted")
            connection.response("226", "abort successful")

    return wrapper

class Server:
    def __init__(self, user_manager, path_io):
        self.path_io_factory = PathIONursery(path_io)
        self.user_manager = user_manager

        self.available_connections = AvailableConnections(32)
        self.commands_mapping = {
            "abor": self.abor,
            "appe": self.appe,
            "cdup": self.cdup,
            "cwd": self.cwd,
            "dele": self.dele,
            "epsv": self.epsv,
            "list": self.list,
            "mkd": self.mkd,
            "mlsd": self.mlsd,
            "mlst": self.mlst,
            "pass": self.pass_,
            "pasv": self.pasv,
            "pbsz": self.pbsz,
            "prot": self.prot,
            "pwd": self.pwd,
            "quit": self.quit,
            "rest": self.rest,
            "retr": self.retr,
            "rmd": self.rmd,
            "rnfr": self.rnfr,
            "rnto": self.rnto,
            "stor": self.stor,
            "syst": self.syst,
            "type": self.type,
            "user": self.user,
        }

    async def start(self, host="0.0.0.0", port=9021, **kwargs):
        self._before_start = None
        self._start_server_extra_arguments = kwargs
        self.connections = {}
        self.server_host = host
        self.server_port = port
        self.server = await start_server(self.dispatcher, host, port, ssl=None, **self._start_server_extra_arguments)
        for sock in self.server.sockets:
            if sock.family in (AF_INET, AF_INET6):
                host, port, *_ = sock.getsockname()
                if not self.server_port:
                    self.server_port = port
                if not self.server_host:
                    self.server_host = host

    async def serve_forever(self):
        return await self.server.serve_forever()

    async def run(self, host="0.0.0.0", port=9021, **kwargs):
        await self.start(host=host, port=port, **kwargs)
        try:
            await self.serve_forever()
        finally:
            await self.close()

    @property
    def address(self):
        return self.server_host, self.server_port

    async def close(self):
        self.server.close()
        tasks = [create_task(self.server.wait_closed())]
        for connection in self.connections.values():
            connection._dispatcher.cancel()
            tasks.append(connection._dispatcher)
        await wait(tasks)

    async def write_line(self, stream, line):
        await stream.write((line + "\r\n").encode("utf-8"))

    async def write_response(self, stream, code, lines="", list=False):
        lines = wrap_with_container(lines)
        write = partial(self.write_line, stream)
        if list:
            head, *body, tail = lines
            await write(code + "-" + head)
            for line in body:
                await write(" " + line)
            await write(code + " " + tail)
        else:
            *body, tail = lines
            for line in body:
                await write(code + "-" + line)
            await write(code + " " + tail)

    async def parse_command(self, stream, censor_commands=("pass",)):
        line = await stream.readline()
        if not line:
            raise ConnectionResetError
        encoding = cdetect(line)['encoding'] or "utf8"
        s = line.decode(encoding).rstrip()
        cmd, _, rest = s.partition(" ")

        return cmd.lower(), rest

    async def response_writer(self, stream, response_queue):
        while True:
            args = await response_queue.get()
            try:
                await self.write_response(stream, *args)
            finally:
                response_queue.task_done()

    async def dispatcher(self, reader, writer):
        host, port, *_ = writer.transport.get_extra_info("peername", ("", ""))
        current_server_host, *_ = writer.transport.get_extra_info("sockname")
        key = stream = StreamIO(reader, writer)
        response_queue = Queue()
        connection = Connection(
            server_host=current_server_host,
            server_port=self.server_port,
            command_connection=stream,
            path_io_factory=self.path_io_factory,
            extra_workers=set(),
            response=lambda *args: response_queue.put_nowait(args),
            acquired=False,
            restart_offset=0,
            _dispatcher=current_task(),
        )
        connection.path_io = self.path_io_factory(connection=connection)
        pending = {
            create_task(self.greeting(connection, "")),
            create_task(self.response_writer(stream, response_queue)),
            create_task(self.parse_command(stream)),
        }
        self.connections[key] = connection
        try:
            while True:
                done, pending = await wait(pending | connection.extra_workers, return_when=FIRST_COMPLETED)
                connection.extra_workers -= done
                for task in done:
                    try:
                        result = task.result()
                    except PathIOError as e:
                        connection.response("451", "file system error")
                        continue
                    if isinstance(result, bool):
                        if not result:
                            await response_queue.join()
                            return
                    elif isinstance(result, tuple):
                        pending.add(create_task(self.parse_command(stream)))
                        cmd, rest = result
                        f = self.commands_mapping.get(cmd)
                        if f is not None:
                            pending.add(create_task(f(connection, rest)))
                            if cmd not in ("retr", "stor", "appe"):
                                connection.restart_offset = 0
                        else:
                            message = f"{cmd!r} not implemented"
                            connection.response("502", message)
        except CancelledError:
            raise
        except:
            pass
        finally:
            tasks_to_wait = []
            if not get_running_loop().is_closed():
                for task in pending | connection.extra_workers:
                    task.cancel()
                    tasks_to_wait.append(task)
                if connection.future.passive_server.done():
                    connection.passive_server.close()
                if connection.future.data_connection.done():
                    connection.data_connection.close()
                stream.close()
            if connection.acquired:
                self.available_connections.release()
            if connection.future.user.done():
                task = create_task(self.user_manager.notify_logout(connection.user))
                tasks_to_wait.append(task)
            self.connections.pop(key)
            if tasks_to_wait:
                await wait(tasks_to_wait)

    @staticmethod
    def get_paths(connection, path):
        virtual_path = PurePosixPath(path)
        if not virtual_path.is_absolute():
            virtual_path = connection.current_directory / virtual_path
        resolved_virtual_path = PurePosixPath("/")
        for part in virtual_path.parts[1:]:
            if part == "..":
                resolved_virtual_path = resolved_virtual_path.parent
            else:
                resolved_virtual_path /= part
        base_path = connection.user.base_path
        real_path = base_path / resolved_virtual_path.relative_to("/")
        # replace with `is_relative_to` check after 3.9+ requirements lands
        try:
            real_path.relative_to(base_path)
        except ValueError:
            real_path = base_path
            resolved_virtual_path = PurePosixPath("/")
        return real_path, resolved_virtual_path

    async def greeting(self, connection, rest):
        if self.available_connections.locked():
            ok, code, info = False, "421", "Too many connections"
        else:
            ok, code, info = True, "220", "welcome"
            connection.acquired = True
            self.available_connections.acquire()
        connection.response(code, info)
        return ok

    async def user(self, connection, rest):
        if connection.future.user.done():
            await self.user_manager.notify_logout(connection.user)
        del connection.user
        del connection.logged
        state, user, info = await self.user_manager.get_user(rest)
        if state == AbstractUserManager.GetUserResponse.PASSWORD_REQUIRED:
            code = "331"
            connection.user = user
        elif state == AbstractUserManager.GetUserResponse.ERROR:
            code = "530"
        else:
            message = f"Unknown response {state}"
            raise NotImplementedError(message)

        if connection.future.user.done():
            connection.current_directory = connection.user.home_path
        connection.response(code, info)
        return True

    @ConnectionConditions(ConnectionConditions.user_required)
    async def pass_(self, connection, rest):
        if connection.future.logged.done():
            code, info = "503", "already logged in"
        elif await self.user_manager.authenticate(connection.user, rest):
            connection.logged = True
            code, info = "230", "normal login"
        else:
            code, info = "530", "wrong password"
        await connection.path_io.mkdir(connection.user.home_path, exist_ok=True)
        connection.response(code, info)
        return True

    async def quit(self, connection, rest):
        connection.response("221", "bye")
        return False

    @ConnectionConditions(ConnectionConditions.login_required)
    async def pwd(self, connection, rest):
        code, info = "257", f"\"{connection.current_directory}\""
        connection.response(code, info)
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    @PathConditions(PathConditions.path_must_exists, PathConditions.path_must_be_dir)
    @PathPermissions(PathPermissions.readable)
    async def cwd(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        connection.current_directory = virtual_path
        connection.response("250", "")
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    async def cdup(self, connection, rest):
        return await self.cwd(connection, connection.current_directory.parent)

    @ConnectionConditions(ConnectionConditions.login_required)
    @PathConditions(PathConditions.path_must_not_exists)
    @PathPermissions(PathPermissions.writable)
    async def mkd(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        await connection.path_io.mkdir(real_path)
        connection.response("257", "")
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    @PathConditions(PathConditions.path_must_exists, PathConditions.path_must_be_dir)
    @PathPermissions(PathPermissions.writable)
    async def rmd(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        await connection.path_io.rmdir(real_path)
        connection.response("250", "")
        return True

    @staticmethod
    def _format_mlsx_time(local_seconds):
        return strftime("%Y%m%d%H%M%S", gmtime(local_seconds))

    def _build_mlsx_facts_from_stats(self, stats):
        return {
            "Size": stats.st_size,
            "Create": self._format_mlsx_time(stats.st_ctime),
            "Modify": self._format_mlsx_time(stats.st_mtime),
        }

    async def build_mlsx_string(self, connection, path):
        if not await connection.path_io.exists(path):
            facts = {}
        else:
            stats = await connection.path_io.stat(path)
            facts = self._build_mlsx_facts_from_stats(stats)
        if await connection.path_io.is_file(path):
            facts["Type"] = "file"
        elif await connection.path_io.is_dir(path):
            facts["Type"] = "dir"
        else:
            facts["Type"] = "unknown"

        s = ""
        for name, value in facts.items():
            s += f"{name}={value};"
        s += " " + path.name
        return s

    @ConnectionConditions(ConnectionConditions.login_required, ConnectionConditions.passive_server_started)
    @PathConditions(PathConditions.path_must_exists)
    @PathPermissions(PathPermissions.readable)
    async def mlsd(self, connection, rest):
        @ConnectionConditions(ConnectionConditions.data_connection_made, wait=True, fail_code="425", fail_info="Can't open data connection")
        @worker
        async def mlsd_worker(self, connection, rest):
            stream = connection.data_connection
            del connection.data_connection
            async with stream:
                async for path in connection.path_io.list(real_path):
                    s = await self.build_mlsx_string(connection, path)
                    b = (s + "\r\n").encode("utf-8")
                    await stream.write(b)
            connection.response("200", "mlsd transfer done")
            return True

        real_path, virtual_path = self.get_paths(connection, rest)
        coro = mlsd_worker(self, connection, rest)
        task = create_task(coro)
        connection.extra_workers.add(task)
        connection.response("150", "mlsd transfer started")
        return True

    @staticmethod
    def build_list_mtime(st_mtime, now=None):
        if now is None:
            now = time()
        mtime = localtime(st_mtime)
        with setlocale("C"):
            if now - 15778476 < st_mtime <= now:
                s = strftime("%b %e %H:%M", mtime)
            else:
                s = strftime("%b %e  %Y", mtime)
        return s

    async def build_list_string(self, connection, path):
        stats = await connection.path_io.stat(path)
        mtime = self.build_list_mtime(stats.st_mtime)
        fields = (filemode(stats.st_mode), str(stats.st_nlink), "none", "none", str(stats.st_size), mtime, path.name)
        s = " ".join(fields)
        return s

    @ConnectionConditions(ConnectionConditions.login_required, ConnectionConditions.passive_server_started)
    @PathConditions(PathConditions.path_must_exists)
    @PathPermissions(PathPermissions.readable)
    async def list(self, connection, rest):
        @ConnectionConditions(ConnectionConditions.data_connection_made, wait=True, fail_code="425", fail_info="Can't open data connection")
        @worker
        async def list_worker(self, connection, rest):
            stream = connection.data_connection
            del connection.data_connection
            async with stream:
                async for path in connection.path_io.list(real_path):
                    s = await self.build_list_string(connection, path)
                    b = (s + "\r\n").encode("utf-8")
                    await stream.write(b)
            connection.response("226", "list transfer done")
            return True

        real_path, virtual_path = self.get_paths(connection, rest)
        coro = list_worker(self, connection, rest)
        task = create_task(coro)
        connection.extra_workers.add(task)
        connection.response("150", "list transfer started")
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    @PathConditions(PathConditions.path_must_exists)
    @PathPermissions(PathPermissions.readable)
    async def mlst(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        s = await self.build_mlsx_string(connection, real_path)
        connection.response("250", ["start", s, "end"], True)
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    @PathConditions(PathConditions.path_must_exists)
    @PathPermissions(PathPermissions.writable)
    async def rnfr(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        connection.rename_from = real_path
        connection.response("350", "rename from accepted")
        return True

    @ConnectionConditions(ConnectionConditions.login_required, ConnectionConditions.rename_from_required)
    @PathConditions(PathConditions.path_must_not_exists)
    @PathPermissions(PathPermissions.writable)
    async def rnto(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        rename_from = connection.rename_from
        del connection.rename_from
        await connection.path_io.rename(rename_from, real_path)
        connection.response("250", "")
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    @PathConditions(PathConditions.path_must_exists, PathConditions.path_must_be_file)
    @PathPermissions(PathPermissions.writable)
    async def dele(self, connection, rest):
        real_path, virtual_path = self.get_paths(connection, rest)
        await connection.path_io.unlink(real_path)
        connection.response("250", "")
        return True

    @ConnectionConditions(ConnectionConditions.login_required, ConnectionConditions.passive_server_started)
    @PathPermissions(PathPermissions.writable)
    async def stor(self, connection, rest, mode="wb"):
        @ConnectionConditions(ConnectionConditions.data_connection_made, wait=True, fail_code="425", fail_info="Can't open data connection")
        @worker
        async def stor_worker(self, connection, rest):
            stream = connection.data_connection
            del connection.data_connection
            if connection.restart_offset:
                file_mode = "r+b"
            else:
                file_mode = mode
            file_out = await connection.path_io.open(real_path, mode=file_mode)
            async with file_out, stream:
                if connection.restart_offset:
                    await file_out.seek(connection.restart_offset)
                await file_out.write_stream(stream)
            connection.response("226", "data transfer done")
            return True

        real_path, virtual_path = self.get_paths(connection, rest)
        if await connection.path_io.is_dir(real_path.parent):
            coro = stor_worker(self, connection, rest)
            task = create_task(coro)
            connection.extra_workers.add(task)
            code, info = "150", "data transfer started"
        else:
            code, info = "550", "path unreachable"
        connection.response(code, info)
        return True

    @ConnectionConditions(ConnectionConditions.login_required, ConnectionConditions.passive_server_started)
    @PathConditions(PathConditions.path_must_exists, PathConditions.path_must_be_file)
    @PathPermissions(PathPermissions.readable)
    async def retr(self, connection, rest):
        @ConnectionConditions(ConnectionConditions.data_connection_made, wait=True, fail_code="425", fail_info="Can't open data connection")
        @worker
        async def retr_worker(self, connection, rest):
            stream = connection.data_connection
            del connection.data_connection
            file_in = await connection.path_io.open(real_path, mode="rb")
            async with file_in, stream:
                if connection.restart_offset:
                    await file_in.seek(connection.restart_offset)
                async for data in file_in.iter_by_block(8192):
                    await stream.write(data)
            connection.response("226", "data transfer done")
            return True

        real_path, virtual_path = self.get_paths(connection, rest)
        coro = retr_worker(self, connection, rest)
        task = create_task(coro)
        connection.extra_workers.add(task)
        connection.response("150", "data transfer started")
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    async def type(self, connection, rest):
        if rest in ("I", "A"):
            connection.transfer_type = rest
            code, info = "200", ""
        else:
            code, info = "502", f"type {rest!r} not implemented"
        connection.response(code, info)
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    async def pbsz(self, connection, rest):
        connection.response("200", "")
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    async def prot(self, connection, rest):
        if rest == "P":
            code, info = "200", ""
        else:
            code, info = "502", ""
        connection.response(code, info)
        return True

    async def _start_passive_server(self, connection, handler_callback):
        passive_server = await start_server(handler_callback, connection.server_host, 0, ssl=None, **self._start_server_extra_arguments,)
        return passive_server

    @ConnectionConditions(ConnectionConditions.login_required)
    async def pasv(self, connection, rest):
        async def handler(reader, writer):
            if connection.future.data_connection.done():
                writer.close()
            else:
                connection.data_connection = StreamIO(reader, writer)

        if not connection.future.passive_server.done():
            coro = self._start_passive_server(connection, handler)
            try:
                connection.passive_server = await coro
            except NoAvailablePort:
                connection.response("421", ["no free ports"])
                return False
            code, info = "227", ["listen socket created"]
        else:
            code, info = "227", ["listen socket already exists"]

        for sock in connection.passive_server.sockets:
            if sock.family == AF_INET:
                host, port = sock.getsockname()
                break
        else:
            connection.response("503", ["this server started in ipv6 mode"])
            return False

        nums = tuple(map(int, host.split("."))) + (port >> 8, port & 0xff)
        info.append(f"({','.join(map(str, nums))})")
        if connection.future.data_connection.done():
            connection.data_connection.close()
            del connection.data_connection
        connection.response(code, info)
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    async def epsv(self, connection, rest):
        async def handler(reader, writer):
            if connection.future.data_connection.done():
                writer.close()
            else:
                connection.data_connection = StreamIO(reader, writer)

        if rest:
            code, info = "522", ["custom protocols support not implemented"]
            connection.response(code, info)
            return False
        if not connection.future.passive_server.done():
            coro = self._start_passive_server(connection, handler)
            try:
                connection.passive_server = await coro
            except NoAvailablePort:
                connection.response("421", ["no free ports"])
                return False
            code, info = "229", ["listen socket created"]
        else:
            code, info = "229", ["listen socket already exists"]

        for sock in connection.passive_server.sockets:
            if sock.family in (AF_INET, AF_INET6):
                _, port, *_ = sock.getsockname()
                break

        info[0] += f" (|||{port}|)"
        if connection.future.data_connection.done():
            connection.data_connection.close()
            del connection.data_connection
        connection.response(code, info)
        return True

    @ConnectionConditions(ConnectionConditions.login_required)
    async def abor(self, connection, rest):
        if connection.extra_workers:
            for worker in connection.extra_workers:
                worker.cancel()
        else:
            connection.response("226", "nothing to abort")
        return True

    async def appe(self, connection, rest):
        return await self.stor(connection, rest, "ab")

    async def rest(self, connection, rest):
        if rest.isdigit():
            connection.restart_offset = int(rest)
            connection.response("350", f"restarting at {rest}")
        else:
            connection.restart_offset = 0
            message = f"syntax error, can't restart at {rest!r}"
            connection.response("501", message)
        return True

    async def syst(self, connection, rest):
        connection.response("215", "UNIX Type: L8")
        return True
