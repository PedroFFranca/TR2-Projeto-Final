#Para parar o tracker, use o comando: kill -9 $(lsof -t -i:5000)
#ou então ao na area de login/register escreva close na escolha:
import socket
import json
import hashlib
import threading
import time
import os

FILE_LOCK = threading.Lock()

class Usuario:
    def __init__(self, login, senha):
        self.login = login
        self.senha = self.hash_senha(senha)
        self.ativo = True
    
    @staticmethod
    def hash_senha(senha):
        return hashlib.sha256(senha.encode()).hexdigest()

    @classmethod
    def criar_login(cls, login, senha):
        if not login or not senha:
            print("Login ou senha não podem ser vazios!")
            return None
        with open("user.json", "r") as f:
            data = json.load(f)
            if login in data:
                print("Login já existe!")
                return None
            else:
                data[login] = {
                'senha': cls.hash_senha(senha), 
                "ativo": True,
                "reputacao": {
                    "upload_bytes": 0,
                    "tempo_online_segundos": 0,
                    "respostas_sucesso": 0
                }
                }
                with open('user.json', 'w') as f:
                    json.dump(data, f, indent=4)
                print("Login criado com sucesso!")
                return cls(login, senha)

    @classmethod
    def verificar_login(cls, login, senha):
        with open("user.json", "r") as f:
            data = json.load(f)
            if login in data and data[login]['senha'] == cls.hash_senha(senha):
                print("Login e senha corretos!")
                return cls(login, senha)
            else:
                print("Login ou senha incorretos!")
                return None
    @staticmethod
    def marcar_usuario_inativo(login):
        with open("user.json", "r") as f:
            data = json.load(f)
        if login in data:
            data[login]["ativo"] = False
            with open("user.json", "w") as f:
                json.dump(data, f, indent=4)
        print(f"Usuário {login} marcado como inativo.")
    
    @staticmethod
    def atualizar_tempo_online(login, duracao_segundos):
        with FILE_LOCK: # Protege a operação de arquivo
            with open("user.json", "r+") as f:
                data = json.load(f)
                if login in data:
                    # Incrementa o tempo online do usuário
                    if 'reputacao' not in data[login]:
                        data[login]['reputacao'] = {
                        "upload_bytes": 0,
                        "tempo_online_segundos": 0,
                        "respostas_sucesso": 0
                        }
                    
                    data[login]['reputacao']['tempo_online_segundos'] += duracao_segundos
                    f.seek(0)
                    json.dump(data, f, indent=4)
                    f.truncate()
    @staticmethod
    def atualizar_estatisticas_upload(uploader_login, bytes_transferidos):
        with FILE_LOCK: # Protege a operação de arquivo
            with open("user.json", "r+") as f:
                data = json.load(f)
                if uploader_login in data:
                    # Incrementa os contadores de reputação
                    if 'reputacao' not in data[uploader_login]:
                        data[uploader_login]['reputacao'] = {
                        "upload_bytes": 0,
                        "tempo_online_segundos": 0,
                        "respostas_sucesso": 0
                        }
                    
                    reputacao = data[uploader_login]['reputacao']
                    reputacao['upload_bytes'] += bytes_transferidos
                    reputacao['respostas_sucesso'] += 1

                    f.seek(0)
                    json.dump(data, f, indent=4)
                    f.truncate()
    @staticmethod
    def calcular_score_reputacao(reputacao_dict):
        """
        Calcula um score único com base nas métricas de reputação.
        Retorna 0 se o dicionário de reputação não existir.
        """
        if not reputacao_dict:
            return 0

        # Pesos para cada métrica (podem ser ajustados)
        W_UPLOAD = 1.0  # 1 ponto por cada KB transferido
        W_TIME = 0.001  # 1 ponto a cada ~16 minutos online
        W_SUCCESS = 10  # 10 pontos por cada chunk servido com sucesso

        # Pegando os valores com .get() para evitar erros se a chave não existir
        upload_kb = reputacao_dict.get("upload_bytes", 0) / 1024
        tempo_s = reputacao_dict.get("tempo_online_segundos", 0)
        respostas = reputacao_dict.get("respostas_sucesso", 0)

        score = (upload_kb * W_UPLOAD) + (tempo_s * W_TIME) + (respostas * W_SUCCESS)
        return score

class Arquivo:
    def __init__(self, nome, conteudo, peer):
        self.nome = nome
        self.conteudo = Usuario.hash_senha(conteudo)
        self.tamanho = len(conteudo)
        self.peers = [peer]
    @classmethod
    def adicionar_arquivo(cls, nome_arquivo, dados_do_peer, peer_login):
        with open("arquivos.json", "r+") as f:
            data = json.load(f)
            file_hash = dados_do_peer.get("conteudo") # O "conteudo" enviado é o hash
            file_size = dados_do_peer.get("file_size")

            if nome_arquivo in data:
                # Se o arquivo já existe, apenas adiciona o peer à lista se ele não estiver lá
                if peer_login not in data[nome_arquivo]['peers']:
                    data[nome_arquivo]['peers'].append(peer_login)
            else:
                # Se o arquivo é novo, cria a entrada completa
                data[nome_arquivo] = {
                    'hash': file_hash, 
                    'size': file_size, 
                    'peers': [peer_login]
                }
            
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
    
        resposta = {"aprovado": True, "texto": "Arquivo adicionado/atualizado com sucesso!"}
        return resposta
    @classmethod
    def baixar_arquivo(cls, nome_arquivo, peer, resposta):
        with open("arquivos.json", "r") as f:
            data = json.load(f)
            if nome_arquivo in data:
                if peer not in data[nome_arquivo]['peers']:
                    data[nome_arquivo]['peers'].append(peer)
                    with open('arquivos.json', 'w') as f:
                        json.dump(data, f, indent=4)
                    print("Arquivo baixado com sucesso!")
                    resposta["aprovado"] = True
                    resposta["texto"] = "Arquivo baixado com sucesso!"
                    return resposta
                else:
                    print("Você já baixou este arquivo!")
                    resposta["aprovado"] = False
                    resposta["texto"] = "Você já baixou este arquivo!"
                    return resposta
            else:
                print("Arquivo não encontrado!")
                resposta["aprovado"] = False
                resposta["texto"] = "Arquivo não encontrado!"
                return resposta

class GerenciadorMensagens:
    """
    Gerencia o armazenamento e recuperação de mensagens offline de forma thread-safe.
    """
    def __init__(self, offline_msg_file="offline_messages.json"):
        self.offline_msg_file = offline_msg_file
        self.lock = threading.Lock()
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        """Garante que o arquivo JSON exista."""
        with self.lock:
            if not os.path.exists(self.offline_msg_file):
                with open(self.offline_msg_file, 'w') as f:
                    json.dump({}, f)

    def store_message(self, recipient: str, message_data: dict):
        """Armazena uma mensagem para um usuário que está offline."""
        with self.lock:
            with open(self.offline_msg_file, "r+") as f:
                data = json.load(f)
                
                # Se o destinatário não tiver uma "caixa de entrada", cria uma
                if recipient not in data:
                    data[recipient] = []
                
                # Adiciona a nova mensagem
                data[recipient].append(message_data)
                
                # Salva o arquivo de volta
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()

    def retrieve_and_clear_messages(self, recipient: str) -> list:
        """Recupera as mensagens de um usuário e limpa sua caixa de entrada."""
        messages = []
        with self.lock:
            with open(self.offline_msg_file, "r+") as f:
                data = json.load(f)
                
                messages = data.pop(recipient, [])
                
                # Salva o arquivo de volta, agora sem as mensagens que foram entregues.
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
        return messages


class TrackerP2P:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('localhost', 5000))
        self.server.listen()
        print("Servidor P2P iniciado em localhost...")
        self.active_peers = {}
        self.peers_lock = threading.Lock()
        self.clients = []
        self.message_manager = GerenciadorMensagens()

    def handle_client(self, client, addr):
        print(f"Nova conexão de {addr}")
        current_user_login = None
        login_time = None
        try:
            while True:
                dado_bytes = client.recv(2048)
                if not dado_bytes:
                    break
                
                dados = json.loads(dado_bytes.decode())
                
                resposta = {"aprovado": False, "texto": "", "dados": None}
                comando = dados.get("op")

                if comando == "1" or comando == "register":  # Registrar
                    usuario = Usuario.criar_login(dados["usuario"], dados["senha"])
                    if usuario:
                        resposta["aprovado"] = True
                        resposta["texto"] = "Usuário registrado com sucesso!"
                    else:
                        resposta["texto"] = "Erro: Login já existe ou dados inválidos."

                elif comando == "2" or comando == "login":  # Login
                    usuario = Usuario.verificar_login(dados["usuario"], dados["senha"])
                    if usuario:
                        p2p_port = dados.get("p2p_port")
                        if p2p_port:
                            peer_ip = addr[0]
                            current_user_login = usuario.login
                            login_time = time.time()
                            with self.peers_lock:
                                self.active_peers[current_user_login] = (peer_ip, p2p_port)

                            resposta["aprovado"] = True
                            resposta["texto"] = f"Login realizado com sucesso! Bem-vindo, {current_user_login}."
                            print(f"Peer '{current_user_login}' registrou seu endereço: {peer_ip}:{p2p_port}")
                        else:
                            resposta["texto"] = "Erro: Cliente não informou a porta P2P."
                    else:
                        resposta["texto"] = "Erro: Login ou senha incorretos."

                elif comando == "adicionar":
                    # Certifica que o usuário está logado para adicionar um arquivo
                    if current_user_login:
                        # Passamos o dicionário 'dados' inteiro, que já contém
                        # "conteudo" (o hash) e "file_size".
                        resposta = Arquivo.adicionar_arquivo(
                            nome_arquivo=dados.get("nome_arquivo"), 
                            dados_do_peer=dados,
                            peer_login=current_user_login
                        )
                    else:
                        resposta["texto"] = "Erro: Você precisa estar logado para adicionar arquivos."

                elif comando == "get_peers":
                    nome_arquivo = dados.get("nome_arquivo")
                    if not (current_user_login and nome_arquivo):
                        resposta["texto"] = "Requisição inválida."; client.send(json.dumps(resposta).encode()); continue

                    # 1. Pega informações básicas do arquivo
                    with FILE_LOCK:
                        with open("arquivos.json", "r") as f:
                            arquivos_data = json.load(f)

                    info_arquivo_salvo = arquivos_data.get(nome_arquivo)
                    if not info_arquivo_salvo:
                        resposta["texto"] = "Arquivo não encontrado."; client.send(json.dumps(resposta).encode()); continue

                    # 2. Monta uma lista de candidatos que estão REALMENTE online
                    peers_com_arquivo = info_arquivo_salvo.get("peers", [])
                    candidatos_online = []
                    with self.peers_lock:
                        for login in peers_com_arquivo:
                            if login in self.active_peers:
                                candidatos_online.append({"login": login, "addr": self.active_peers[login]})

                    if not candidatos_online:
                        resposta["texto"] = "Nenhum peer com este arquivo está online."; client.send(json.dumps(resposta).encode()); continue

                    # 3. Calcula o score de cada candidato e os ordena
                    peers_com_score = []
                    with FILE_LOCK:
                        with open("user.json", "r") as f:
                            users_data = json.load(f)
                    
                    for candidato in candidatos_online:
                        user_data = users_data.get(candidato["login"], {})
                        score = Usuario.calcular_score_reputacao(user_data.get("reputacao"))
                        peers_com_score.append({"login": candidato["login"], "addr": candidato["addr"], "score": score})
                    
                    peers_com_score.sort(key=lambda p: p["score"], reverse=True)
                    
                    # 4. Prepara a lista final ordenada (agora com login e endereço)
                    lista_final_ordenada = [{"login": p["login"], "addr": p["addr"]} for p in peers_com_score]

                    # (A lógica de limite dinâmico pode ser adicionada aqui, antes de enviar)
                    
                    # 5. Envia a resposta ordenada para o cliente
                    dados_para_enviar = {
                        "peers": lista_final_ordenada,
                        "file_size": info_arquivo_salvo.get("size"),
                        "file_hash": info_arquivo_salvo.get("hash")
                    }
                    resposta.update({"aprovado": True, "dados": dados_para_enviar, "texto": f"Encontrados {len(lista_final_ordenada)} peers. Lista ordenada por reputação."})
                

                elif comando == "listar":
                    # Este comando pode continuar como está ou ser aprimorado
                    with open("arquivos.json", "r") as f:
                        data = json.load(f)
                    resposta["texto"] = "Arquivos disponíveis:\n" + "\n".join(data.keys())
                    resposta["aprovado"] = True
                    
                elif comando == "send_offline_message":
                    if current_user_login:
                        recipient = dados.get("to")
                        message_object = {
                            "from": current_user_login,
                            "content": dados.get("content"),
                            "timestamp": time.strftime('%H:%M:%S')
                        }
                        # Chama o método do nosso gerenciador
                        self.message_manager.store_message(recipient, message_object)
                        resposta["aprovado"] = True
                        resposta["texto"] = "Mensagem offline armazenada para entrega posterior."
                    else:
                        resposta["texto"] = "Erro: Ação permitida apenas para usuários logados."
        
                elif comando == "get_my_messages":
                    if current_user_login:
                        # Chama o método do nosso gerenciador
                        messages = self.message_manager.retrieve_and_clear_messages(current_user_login)
                        resposta["aprovado"] = True
                        if messages:
                            resposta["texto"] = f"Você recebeu {len(messages)} mensagens offline."
                            resposta["dados"] = messages
                        else:
                            resposta["texto"] = "Nenhuma mensagem offline."
                    else:
                        resposta["texto"] = "Erro: Ação permitida apenas para usuários logados."

                
                elif comando == "sair" or comando == "close":
                    resposta["texto"] = "Desconectando..."
                    resposta["aprovado"] = True
                    client.send(json.dumps(resposta).encode())
                    break
                
                elif comando == "get_peer_addr":
                    target_user = dados.get("username")
                    with self.peers_lock:
                        peer_data = self.active_peers.get(target_user)

                    if peer_data:
                        resposta["aprovado"] = True
                        resposta["dados"] = {"addr": peer_data}
                    else:
                        resposta["texto"] = f"Usuário '{target_user}' não está online."
                
                elif comando == "report_upload":
                    uploader = dados.get("uploader_username")
                    bytes_transf = dados.get("bytes_transferred")

                    if uploader and isinstance(bytes_transf, int):
                        Usuario.atualizar_estatisticas_upload(uploader, bytes_transf)
                        # Nenhuma resposta é necessária para o cliente
                        continue
                else:
                    resposta["texto"] = "Comando inválido."

                
                client.send(json.dumps(resposta).encode())


        except (ConnectionResetError, json.JSONDecodeError, BrokenPipeError) as e:
            print(f"Conexão com {addr} perdida ou corrompida: {e}")
        finally:
            if current_user_login:
                print(f"Peer '{current_user_login}' desconectado.")
                Usuario.marcar_usuario_inativo(current_user_login)
                
                if login_time:
                    session_duration = time.time() - login_time
                    Usuario.atualizar_tempo_online(current_user_login, session_duration)
                    print(f"INFO: Sessão de {current_user_login} durou {session_duration:.2f} segundos.")
                
                with self.peers_lock:
                    if current_user_login in self.active_peers:
                        del self.active_peers[current_user_login]
            
            if client in self.clients:
                self.clients.remove(client)
            client.close()
            print(f"Conexão com {addr} encerrada. Conexões ativas: {len(self.clients)}")

    def iniciar(self):
        try:
            while True:
                client, addr = self.server.accept()
                self.clients.append(client)
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True # Permite que o programa principal saia mesmo com threads ativas
                thread.start()
        except KeyboardInterrupt:
            print("\nDesligando o servidor...")
        finally:
            for client in self.clients:
                client.close()
            
                


# Iniciando o servidor
if __name__ == "__main__":
    tracker = TrackerP2P()
    print("Servidor aguardando conexões...")
    tracker.iniciar()