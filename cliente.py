'''
é possivel mandar mensagem para uma conta q nao existe

'''
import socket
import json
import os
import threading
import time
import hashlib
import math
import shutil # Usaremos para limpar arquivos temporários no futuro
import random
from queue import Queue

def calcular_hash_sha256(dados):
    """Calcula o hash SHA-256 para um bloco de dados (bytes)."""
    return hashlib.sha256(dados).hexdigest()

def dividir_arquivo_em_chunks(filepath, chunk_size=1024*1024):
    """
    Lê um arquivo, o divide em chunks e calcula o hash de cada um.
    Retorna o número total de chunks e uma lista de hashes.
    """
    chunk_hashes = []
    chunk_count = 0
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunk_hashes.append(calcular_hash_sha256(chunk))
                chunk_count += 1
        return chunk_count, chunk_hashes
    except FileNotFoundError:
        return 0, []
        
    

class Peer:

    def __init__(self, tracker_host='127.0.0.1', tracker_port=5000):
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.p2p_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.p2p_port = 0
        self.username = ""
        self.chat_ativo = False
        self.sala_chat_ativa = False
        self.is_logged_in = False
        

        self.my_files_db_path = None
        self.my_shared_files = {}
        
        if not os.path.exists('downloads'):
            os.makedirs('downloads')
    
    def _send_heartbeat(self):
        """Enquanto logado, envia um sinal de vida para o tracker a cada 30 segundos."""
        while self.is_logged_in:
            try:
                self.send_to_tracker({"op": "heartbeat"})
                time.sleep(30)
            except:
                self.is_logged_in = False
                break
        print("INFO: Thread de heartbeat finalizada.")

    def _grupo_chat_receiver(self, group_name):
        """Thread que verifica por novas mensagens de grupo a cada 3 segundos."""
        last_message_count = 0
        while self.chat_ativo:
            try:
                request = {"op": "get_group_chat", "group_name": group_name}
                response = self.send_to_tracker(request)
                if response and response.get("aprovado"):
                    history = response.get("dados", [])
                    if len(history) > last_message_count:
                        new_messages = history[last_message_count:]
                        for msg in new_messages:
                            # Evita imprimir as próprias mensagens que já aparecem ao digitar
                            if msg['from'] != self.username:
                                print(f"\n[{msg['timestamp']}] [{msg['from']}]: {msg['content']}")
                        last_message_count = len(history)
                time.sleep(3) # Pausa de 3 segundos entre cada verificação
            except Exception:
                # Se a conexão com o tracker cair, para o loop
                self.chat_ativo = False

    def _grupo_chat_sender(self, group_name):
        """Thread que aguarda o input do usuário para enviar mensagens."""
        while self.chat_ativo:
            try:
                message_content = input()
                # Limpa a linha atual e reescreve o prompt para uma UI mais limpa
                print("\033[A\033[K", end="") 
                print(f"[{self.username} -> {group_name}]: {message_content}")

                if message_content == "/sair":
                    self.chat_ativo = False
                    break
                
                request = {"op": "send_group_message", "group_name": group_name, "content": message_content}
                self.send_to_tracker(request)
            except (KeyboardInterrupt, EOFError):
                self.chat_ativo = False
                break
        print("Saindo do chat de grupo...")

    def iniciar_chat_em_grupo(self, group_name):
        """Função principal que orquestra as threads de envio e recebimento."""
        self.chat_ativo = True
        #os.system('cls' if os.name == 'nt' else 'clear')
        print(f"--- Entrando no chat do grupo '{group_name}'. Digite '/sair' para terminar. ---")
        
        # Inicia a thread para receber mensagens
        receiver = threading.Thread(target=self._grupo_chat_receiver, args=(group_name,))
        receiver.daemon = True
        receiver.start()
        
        # Inicia a thread para enviar mensagens (e aguarda aqui)
        sender = threading.Thread(target=self._grupo_chat_sender, args=(group_name,))
        sender.daemon = True
        sender.start()
        
        # Mantém a função principal viva enquanto o chat estiver ativo
        while self.chat_ativo:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                self.chat_ativo = False
                
        # Espera a thread de envio terminar (após digitar /sair)
        sender.join() 
        print(f"--- Você saiu do chat do grupo '{group_name}'. ---")    
    
    def _carregar_meus_arquivos(self):
        """Carrega o banco de dados local DEPOIS de saber o nome do arquivo."""
        # Se por algum motivo o caminho não foi definido, não faz nada
        if not self.my_files_db_path:
            return {}
        
        # Se o arquivo do usuário ainda não existe, retorna um dicionário vazio
        if not os.path.exists(self.my_files_db_path):
            return {}
            
        with open(self.my_files_db_path, 'r') as f:
            return json.load(f)

    def _salvar_meus_arquivos(self):
        """Salva as alterações no arquivo de metadados do usuário."""
        if not self.my_files_db_path:
            return
            
        with open(self.my_files_db_path, 'w') as f:
            json.dump(self.my_shared_files, f, indent=4)
    
    def carregar_mensagens_chat(self, sender):
        """Carrega o histórico de chat com um usuário específico."""
        history_dir = f"chats_{self.username}"
        log_filename = f"chat_com_{sender}.txt"
        full_path = os.path.join(history_dir, log_filename)
        
        if not os.path.exists(full_path):
            print("\n" + "-"*15 + f" Histórico da Conversa com {sender} " + "-"*15)

        try:
            with open(full_path, 'r') as log_file:
                print("-"*(42 + len(sender)) + "\n")
                for j in log_file.readlines():
                    print(j.strip())
            
        except Exception as e:
            print(f"Erro ao carregar histórico de chat: {e}")
    
    
    def _salvar_historico_chat(self, sender, message):
        try:
            history_dir = f"chats_{self.username}"
            os.makedirs(history_dir, exist_ok=True)
            log_filename = f"chat_com_{sender}.txt"
            full_path = os.path.join(history_dir, log_filename)
            with open(full_path, 'a') as log_file:
                log_file.write(f"{message}\n")
        except Exception as e:
            print(f"Erro ao salvar histórico de chat: {e}")
    
    def sair_da_sala(self, room_name):
        """Envia um pedido ao tracker para sair de uma sala."""
        if not room_name:
            print("O nome da sala não pode ser vazio.")
            return
        response = self.send_to_tracker({"op": "leave_room", "room_name": room_name})
        if response:
            print(f"[Tracker]: {response.get('texto')}")

    def start_p2p_server(self):
        """Inicia o servidor P2P em uma thread para escutar por outros peers."""
        self.p2p_server_socket.bind(('0.0.0.0', 0))
        self.p2p_server_socket.listen(5)
        self.p2p_port = self.p2p_server_socket.getsockname()[1]
        print(f"INFO: Peer escutando por conexões P2P na porta: {self.p2p_port}")

        while True:
            try:
                peer_conn, _ = self.p2p_server_socket.accept()
                handler_thread = threading.Thread(target=self.handle_peer_request, args=(peer_conn,))
                handler_thread.daemon = True
                handler_thread.start()
            except OSError:
                break
    def _sala_chat_receiver(self, room_name):
        """THREAD 1: Verifica por novas mensagens de grupo a cada 3 segundos."""
        last_message_count = 0
        while self.sala_chat_ativa:
            try:
                request = {"op": "get_room_chat", "room_name": room_name}
                response = self.send_to_tracker(request)
                if response and response.get("aprovado"):
                    history = response.get("dados", [])
                    if len(history) > last_message_count:
                        new_messages = history[last_message_count:]
                        for msg in new_messages:
                            if msg['from'] != self.username:
                                # \r e ' ' servem para limpar a linha atual antes de imprimir a nova msg
                                print(f"\r{' ' * 80}\r", end="")
                                print(f"[{msg['timestamp']}] [{msg['from']}]: {msg['content']}")
                                print(f"[{self.username} -> {room_name}]: ", end="", flush=True)
                        last_message_count = len(history)
                time.sleep(3)
            except:
                self.sala_chat_ativa = False

    def _sala_chat_sender(self, room_name):
        """THREAD 2: Aguarda o input do usuário para enviar mensagens."""
        prompt = f"[{self.username} -> {room_name}]: "
        while self.sala_chat_ativa:
            try:
                message_content = input(prompt)
                if message_content == "/sair":
                    self.sala_chat_ativa = False
                    break
                
                request = {"op": "send_room_message", "room_name": room_name, "content": message_content}
                self.send_to_tracker(request)
            except (KeyboardInterrupt, EOFError):
                self.sala_chat_ativa = False
                break
        print("\nSaindo do chat...")

    def iniciar_chat_de_sala(self, room_name):
        """Função principal que orquestra as threads de envio e recebimento."""
        self.sala_chat_ativa = True
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"--- Entrando no chat da sala '{room_name}'. Digite '/sair' para terminar. ---")
        
        # Primeiro, busca e exibe o histórico existente
        response = self.send_to_tracker({"op": "get_room_chat", "room_name": room_name})
        initial_history = []
        if response and response.get("aprovado"):
            initial_history = response.get("dados", [])
            if initial_history:
                print("--- Histórico da Sala ---")
                for msg in initial_history:
                    print(f"[{msg['timestamp']}] [{msg['from']}]: {msg['content']}")
                print("--- Fim do Histórico ---")

        # Inicia a thread para receber mensagens
        receiver = threading.Thread(target=self._sala_chat_receiver, args=(room_name,))
        receiver.daemon = True
        receiver.start()
        
        # A thread principal agora se dedica a enviar mensagens
        self._sala_chat_sender(room_name)

        os.system('cls' if os.name == 'nt' else 'clear')

    def handle_peer_request(self, peer_conn: socket.socket):
        """Lida com as requisições de outros peers (pedir metadados ou chunks)."""
        try:
            request_data = peer_conn.recv(1024).decode()
            request = json.loads(request_data)
            print(request)
            
            op = request.get("op")
            response = {"status": "error", "message": "Invalid operation"}

            if op == "ask_file_metadata":
                filename = request.get("filename")
                if filename in self.my_shared_files:
                    response = {
                        "status": "ok",
                        "metadata": self.my_shared_files[filename]
                    }
            
            elif op == "get_chunk":
                filename = request.get("filename")
                chunk_index = request.get("chunk_index")
                
                if filename in self.my_shared_files:
                    full_path = self.my_shared_files[filename]["full_path"]
                    chunk_size = self.my_shared_files[filename]["chunk_size"]
                    
                    if os.path.exists(full_path):
                        with open(full_path, 'rb') as f:
                            f.seek(chunk_index * chunk_size)
                            chunk_data = f.read(chunk_size)
                        # Envia o dado binário diretamente, sem JSON
                        peer_conn.sendall(chunk_data)
                        return
                    
            elif op == "chat_message":
                sender = request.get("from")
                message = request.get("content")
                print(f"\n[Mensagem de {sender}]: {message}")
                self._salvar_historico_chat(sender, f"[{time.strftime('%H:%M:%S')}] {sender}: {message}")
                return 
            print(response)
            peer_conn.sendall(json.dumps(response).encode())

        except (json.JSONDecodeError, ConnectionResetError, BrokenPipeError, OSError):
            pass # Ignora erros de conexão com outros peers
        finally:
            peer_conn.close()

    def iniciar_chat(self, target_username):
        response = self.send_to_tracker({"op": "get_peer_addr", "username": target_username})
        is_online = response and response.get("aprovado")
        

        #os.system('cls' if os.name == 'nt' else 'clear') # Limpa a tela para o chat
        self.carregar_mensagens_chat(target_username)
        
        print(f"\n--- Chat com {target_username} iniciado. Digite '/sair' para terminar. ---")
        while True:
            message_content = input(f"[{self.username} -> {target_username}]: ")
            if message_content == "/sair":
                break
            if is_online:
                print("Chegamos no is online")
                try:
                    print(response.get("dados", {}).get("addr").get("addr"))
                    target_addr = tuple(response.get("dados", {}).get("addr").get("addr"))
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as chat_sock:
                        chat_sock.connect(target_addr)
                        request = {"op": "chat_message", "from": self.username, "content": message_content}
                        self._salvar_historico_chat(target_username, f"[{time.strftime('%H:%M:%S')}] Eu: {message_content}")
                        chat_sock.send(json.dumps(request).encode())
                except Exception as e:
                    print(f"Erro ao enviar mensagem: {e}")
                    print("Colocaremos a mensagem em cache por enquanto...")
                    print("Peer ficou offline. Enviando como mensagem offline.")
                    self._salvar_historico_chat(target_username, f"[{time.strftime('%H:%M:%S')}] Eu: {message_content}")
                    self.send_to_tracker({"op": "send_offline_message", "to": target_username, "content": message_content})
                    is_online = False
            else:
                print(f"(Enviando mensagem offline para {target_username}...)")
                self._salvar_historico_chat(target_username, f"[{time.strftime('%H:%M:%S')}] Eu: {message_content}")
                self.send_to_tracker({"op": "send_offline_message", "to": target_username, "content": message_content})   
        print(f"--- Chat com {target_username} finalizado. ---")
    
    def adicionar_arquivo_para_compartilhar(self, filepath):
        """Processa um arquivo local, salvando seus metadados para compartilhamento."""
        if not os.path.exists(filepath):
            print("Erro: Arquivo não encontrado.")
            return

        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        chunk_size = 1024 * 1024 # 1MB
        
        print("Calculando hashes dos chunks... Isso pode demorar para arquivos grandes.")
        total_chunks, chunk_hashes = dividir_arquivo_em_chunks(filepath, chunk_size)
        
        self.my_shared_files[filename] = {
            "full_path": filepath,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "chunk_size": chunk_size,
            "chunk_hashes": chunk_hashes
        }
        self._salvar_meus_arquivos() # Salva imediatamente após adicionar
        print(f"Arquivo '{filename}' adicionado à lista de compartilhamento local.")
        
        # Informa ao tracker que agora possui este arquivo
        file_hash = calcular_hash_sha256(open(filepath, 'rb').read())
        req = {"op": "adicionar", "nome_arquivo": filename, "conteudo": file_hash, "file_size": file_size}
        print("Enviando informações do arquivo para o tracker...")
        response = self.send_to_tracker(req)
        print("Tracker respondeu")
        if response:
            print(f"Tracker respondeu: {response.get('texto')}")
        else:
            print("Erro ao comunicar com o tracker. Verifique sua conexão.")

    def _reassemble_file(self, filename, temp_dir, total_chunks, chunk_size):
        """Junta todos os chunks temporários em um único arquivo final."""
        output_path = os.path.join('downloads', filename)
        try:
            print(f"\nRemontando arquivo '{filename}' a partir de {total_chunks} chunks...")
            with open(output_path, "wb") as outfile:
                for i in range(total_chunks):
                    
                    print(f"\rRemontando chunk {i + 1}/{total_chunks}...", end="")
                    
                    chunk_path = os.path.join(temp_dir, f"chunk_{i}.tmp")
                    with open(chunk_path, "rb") as chunkfile:
                        outfile.write(chunkfile.read())
            print("\nArquivo remontado com sucesso!")
            return output_path
        except FileNotFoundError:
            print(f"\nErro Crítico: Chunk #{i} não encontrado durante a remontagem.")
            if os.path.exists(output_path): os.remove(output_path)
            return None

    def _download_worker(self, peer_info, filename, file_metadata, chunk_to_download, temp_dir):
        """
        Função executada por uma thread para baixar um único chunk.
        """
        peer_addr = tuple(peer_info['addr'])
        uploader_username = peer_info['login']

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as download_sock:
                download_sock.settimeout(10)
                download_sock.connect(peer_addr)

                request = {"op": "get_chunk", "filename": filename, "chunk_index": chunk_to_download}
                download_sock.send(json.dumps(request).encode())

                chunk_path = os.path.join(temp_dir, f"chunk_{chunk_to_download}.tmp")
                with open(chunk_path, "wb") as f:
                    # O chunk pode ser grande, recebemos em um loop para garantir
                    received_data = b""
                    while len(received_data) < file_metadata["chunk_size"]:
                        data = download_sock.recv(4096)
                        if not data:
                            break
                        received_data += data
                    f.write(received_data)

                # Validação do chunk com checksum
                chunk_hash_recebido = calcular_hash_sha256(received_data)
                hash_esperado = file_metadata["chunk_hashes"][chunk_to_download]

                if chunk_hash_recebido == hash_esperado:
                    # Sinaliza sucesso colocando o chunk na fila de chunks baixados
                    self.downloaded_chunks_queue.put(chunk_to_download)

                    report = {
                    "op": "report_upload",
                    "uploader_username": uploader_username,
                    "bytes_transferred": len(received_data)
                    }
                    #Envia o relatório para o tracker em modo "fire-and-forget"
                    self.send_to_tracker(report)
                else:
                    print(f"\nFalha de checksum no chunk #{chunk_to_download}. Tentando baixar novamente...")
                    os.remove(chunk_path) # Remove o chunk corrompido
        except Exception as e:
            # A falha será tratada pelo loop principal, que tentará baixar o chunk novamente
            pass


    def _get_metadata_from_peers(self, filename, peer_list):
        """Obtém os metadados detalhados (com hashes de chunks) de um dos peers."""
        for peer_info in peer_list:
            peer_addr = tuple(peer_info['addr'])
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    sock.connect(peer_addr)
                    sock.send(json.dumps({"op": "ask_file_metadata", "filename": filename}).encode())
                    response = json.loads(sock.recv(16384).decode())
                    if response.get("status") == "ok":
                        return response["metadata"]
            except Exception:
                continue
        return None

    def _map_chunk_availability(self, filename, peer_list):
        """Cria um mapa de quais peers possuem quais chunks."""
        chunk_availability = {}
        print("\nMapeando chunks disponíveis nos peers...")
        for peer_info in peer_list:
            peer_addr = tuple(peer_info['addr'])
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    sock.connect(peer_addr)
                    num_chunks = self.file_metadata_cache['total_chunks'] # Usando um cache
                    chunks_do_peer = list(range(num_chunks))
                    
                    for chunk_idx in chunks_do_peer:
                        if chunk_idx not in chunk_availability:
                            chunk_availability[chunk_idx] = []
                        chunk_availability[chunk_idx].append(peer_info)
            except Exception:
                continue
        return chunk_availability

    def _choose_best_peer(self, chunk_idx, chunk_availability, sorted_peer_list):
        """Escolhe o melhor peer (mais alto na lista do tracker) que possui o chunk."""
        peers_com_o_chunk = chunk_availability.get(chunk_idx, [])
        # Converte a lista de dicionários para uma lista de tuplas para fácil comparação
        addrs_com_o_chunk = [tuple(p['addr']) for p in peers_com_o_chunk]
        
        for peer_info in sorted_peer_list:
            if tuple(peer_info['addr']) in addrs_com_o_chunk:
                return peer_info 
        return None

    def download_file_sequencial(self, filename):
        """
        Baixa um arquivo completo de forma sequencial, usando uma única fonte,
        para fins de comparação de desempenho.
        """
        print(f"\n--- Iniciando download SEQUENCIAL de '{filename}' ---")
        
        # --- Etapa 1: Obter Informações do Tracker ---
        print("1/4: Solicitando informações ao tracker...")
        tracker_response = self.send_to_tracker({"op": "get_peers", "nome_arquivo": filename})
        if not tracker_response or not tracker_response.get("aprovado") or not tracker_response.get("dados"):
            print(f"Erro: Não foi possível obter informações do arquivo '{filename}'.")
            return
        
        file_info = tracker_response["dados"]
        peer_list = file_info.get("peers", [])
        main_file_hash = file_info.get("file_hash")

        if not peer_list:
            print("Nenhum peer com o arquivo.")
            return

        # Pega o primeiro peer da lista (o de melhor reputação) como nossa única fonte
        target_peer_info = peer_list[0]
        target_peer_addr = tuple(target_peer_info['addr'])
        
        print(f"2/4: Obtendo metadados detalhados do peer {target_peer_addr}...")
        file_metadata = self._get_metadata_from_peers(filename, [target_peer_info])
        if not file_metadata:
            print("Erro: Não foi possível obter os metadados do peer fonte.")
            return

        total_chunks = file_metadata["total_chunks"]
        chunk_size = file_metadata["chunk_size"]
        
        temp_dir = f"temp_seq_{main_file_hash[:8]}"
        if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)

        print(f"3/4: Iniciando download de {total_chunks} chunks de uma única fonte...")
        start_time = time.time()
        
        try:
            # --- Etapa 3: Loop de Download Sequencial ---
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(target_peer_addr)
                
                for i in range(total_chunks):
                    print(f"\rBaixando chunk {i + 1}/{total_chunks}...", end="")
                    
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(10)
                        sock.connect(target_peer_addr)
                        
                        request = {"op": "get_chunk", "filename": filename, "chunk_index": i}
                        sock.sendall(json.dumps(request).encode())

                        received_data = b""
                        bytes_to_receive = chunk_size
                        if i == total_chunks - 1:
                            rem = file_metadata["file_size"] % chunk_size
                            if rem > 0: bytes_to_receive = rem
                        
                        while len(received_data) < bytes_to_receive:
                            data = sock.recv(8192)
                            if not data: break
                            received_data += data
                        
                        hash_recebido = calcular_hash_sha256(received_data)
                        hash_esperado = file_metadata["chunk_hashes"][i]
                        if hash_recebido != hash_esperado:
                            print(f"\nErro de checksum no chunk #{i}! Abortando.")
                            raise Exception("Checksum Mismatch")

                        chunk_path = os.path.join(temp_dir, f"chunk_{i}.tmp")
                        with open(chunk_path, "wb") as f:
                            f.write(received_data)
                            
        except Exception as e:
            print(f"\nErro durante o download sequencial: {e}")
            shutil.rmtree(temp_dir)
            return

        end_time = time.time()
        print(f"\nDownload dos chunks finalizado. Tempo de transferência: {end_time - start_time:.4f} segundos.")
        
        # --- Etapa 4: Remontagem e Validação Final ---
        print("4/4: Remontando e validando arquivo final...")
        final_path = self._reassemble_file(filename, temp_dir, total_chunks, chunk_size)
        
        if final_path:
            final_hash = calcular_hash_sha256(open(final_path, 'rb').read())
            if final_hash == main_file_hash:
                print(f"\nSUCESSO! Arquivo '{filename}' validado com sucesso.")
                self.adicionar_arquivo_para_compartilhar(final_path)
            else:
                print("\nERRO DE VALIDAÇÃO! O hash do arquivo final não corresponde ao original.")
            
        shutil.rmtree(temp_dir)

    def criar_grupo(self, group_name):
        """Envia um pedido ao tracker para criar um novo grupo."""
        if not group_name:
            print("O nome do grupo não pode ser vazio.")
            return
        request = {"op": "create_group", "group_name": group_name}
        response = self.send_to_tracker(request)
        if response:
            print(f"[Tracker]: {response.get('texto')}")

    def entrar_em_grupo(self, group_name):
        """Envia um pedido ao tracker para entrar em um grupo existente."""
        if not group_name:
            print("O nome do grupo não pode ser vazio.")
            return
        request = {"op": "join_group", "group_name": group_name}
        response = self.send_to_tracker(request)
        if response:
            print(f"[Tracker]: {response.get('texto')}")
    
    def download_file(self, filename):
        """Orquestra o download paralelo usando a lógica robusta."""
        print(f"\n--- Iniciando download PARALELO de '{filename}' ---")
        start_time = time.time()
        # 1. Obter informações do Tracker
        print("1/5: Solicitando informações ao tracker...")
        tracker_response = self.send_to_tracker({"op": "get_peers", "nome_arquivo": filename})
        if not tracker_response or not tracker_response.get("aprovado") or not tracker_response.get("dados"):
            print(f"Erro: Não foi possível obter informações do arquivo '{filename}'.")
            return

        file_info = tracker_response["dados"]
        peer_list = file_info.get("peers", []) # Agora é uma lista de dicionários: [{'login': ..., 'addr': (...)}}]
        file_size = file_info.get("file_size")
        main_file_hash = file_info.get("file_hash")

        if not peer_list: print("Nenhum peer possui este arquivo."); return

        # 2. Obter metadados detalhados
        print("2/5: Obtendo metadados detalhados de um peer...")
        self.file_metadata_cache = self._get_metadata_from_peers(filename, peer_list)
        if not self.file_metadata_cache:
            print("Erro: Não foi possível obter os metadados de nenhum peer online.")
            return

        # 3. Mapear disponibilidade de chunks
        print("3/5: Mapeando disponibilidade de chunks...")
        chunk_availability = self._map_chunk_availability(filename, peer_list)

        # 4. Iniciar Download Paralelo
        total_chunks = self.file_metadata_cache["total_chunks"]
        owned_chunks = set()
        self.chunks_in_progress = set()
        self.progress_lock = threading.Lock()
        self.downloaded_chunks_queue = Queue()

        print(f"\n4/5: Iniciando download paralelo de {total_chunks} chunks...")
        temp_dir = f"temp_{main_file_hash[:8]}"
        if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)

        active_threads = []
        MAX_CONCURRENT_DOWNLOADS = 8

        while len(owned_chunks) < total_chunks:
            # Processa chunks que terminaram com sucesso
            while not self.downloaded_chunks_queue.empty():
                owned_chunks.add(self.downloaded_chunks_queue.get())

            active_threads = [t for t in active_threads if t.is_alive()]

            # Loop para iniciar novos trabalhadores se houver espaço
            while len(active_threads) < MAX_CONCURRENT_DOWNLOADS:
                with self.progress_lock:
                    chunks_to_consider = [c for c in range(total_chunks) if c not in owned_chunks and c not in self.chunks_in_progress]
                
                if not chunks_to_consider: break

                rarity_list = sorted([(len(chunk_availability.get(c, [])), c) for c in chunks_to_consider])
                if not rarity_list or rarity_list[0][0] == 0:
                    break 

                chunk_to_download = rarity_list[0][1]
                
                peer_info_escolhido = self._choose_best_peer(chunk_to_download, chunk_availability, peer_list)
                if not peer_info_escolhido:
                    # Se não encontrar ninguém, remove este chunk da consideração por um tempo para não travar
                    with self.progress_lock: self.chunks_in_progress.add(chunk_to_download)
                    continue

                with self.progress_lock:
                    self.chunks_in_progress.add(chunk_to_download)
                
                thread = threading.Thread(target=self._download_worker, args=(peer_info_escolhido, filename, self.file_metadata_cache, chunk_to_download, temp_dir))
                thread.daemon = True
                thread.start()
                active_threads.append(thread)
            
            print(f"\rProgresso: {len(owned_chunks)}/{total_chunks} chunks. Downloads ativos: {len(active_threads)}", end="")
            if len(owned_chunks) == total_chunks: break
            time.sleep(0.2)

        end_time = time.time()
        print(f"\n--- Download PARALELO finalizado. Tempo total: {end_time - start_time:.4f} segundos ---")
        # 5. Remontagem e Validação Final
        print("\n5/5: Download completo. Remontando e validando arquivo...")
        final_path = self._reassemble_file(filename, temp_dir, total_chunks, self.file_metadata_cache["chunk_size"])
        if final_path:
            final_hash = calcular_hash_sha256(open(final_path, 'rb').read())
            if final_hash == main_file_hash:
                print(f"\nSUCESSO! Arquivo '{filename}' validado com sucesso.")
                self.adicionar_arquivo_para_compartilhar(final_path)
            else:
                print("\nERRO DE VALIDAÇÃO! O hash do arquivo final não corresponde ao original.")
        
        shutil.rmtree(temp_dir)

    def send_to_tracker(self, request):
        self.tracker_socket.send(json.dumps(request).encode())
        response_bytes = self.tracker_socket.recv(4096)
        if not response_bytes:
            return None
        return json.loads(response_bytes.decode())
    def criar_sala(self, room_name):
        response = self.send_to_tracker({"op": "create_room", "room_name": room_name})
        if response: print(f"[Tracker]: {response.get('texto')}")

    def apagar_sala(self, room_name):
        response = self.send_to_tracker({"op": "delete_room", "room_name": room_name})
        if response: print(f"[Tracker]: {response.get('texto')}")

    def convidar_para_sala(self, room_name, target_user):
        req = {"op": "invite_to_room", "room_name": room_name, "target_user": target_user}
        response = self.send_to_tracker(req)
        if response: print(f"[Tracker]: {response.get('texto')}")

    def expulsar_da_sala(self, room_name, target_user):
        req = {"op": "kick_from_room", "room_name": room_name, "target_user": target_user}
        response = self.send_to_tracker(req)
        if response: print(f"[Tracker]: {response.get('texto')}")

    def listar_salas(self):
        response = self.send_to_tracker({"op": "list_rooms"})
        if response and response.get("aprovado"):
            print("\nSalas disponíveis:")
            for room in response.get("dados", []):
                print(f"- {room}")
        elif response:
            print(f"[Tracker]: {response.get('texto')}")

    def listar_membros_sala(self, room_name):
        response = self.send_to_tracker({"op": "list_room_members", "room_name": room_name})
        if response and response.get("aprovado"):
            details = response.get("dados", {})
            print(f"\n--- Detalhes da Sala: {room_name} ---")
            print(f"Moderador: {details.get('moderador')}")
            print(f"Membros Autorizados: {', '.join(details.get('membros_autorizados', []))}")
            print(f"Membros Online: {', '.join(details.get('membros_online', []))}")
        elif response:
            print(f"[Tracker]: {response.get('texto')}")


    def _menu_salas(self):
        """Exibe o submenu de gerenciamento e interação com salas de chat."""
        os.system('cls' if os.name == 'nt' else 'clear')
        while True:
            print("\n--- Menu de Salas de Chat ---")
            print("1 - Listar todas as salas")
            print("2 - Criar uma nova sala (você será o moderador)")
            print("3 - Entrar no chat de uma sala")
            print("4 - Convidar um usuário para sua sala")
            print("5 - Remover um usuário da sua sala")
            print("6 - Apagar sua sala (apenas moderador)")
            print("7 - Ver membros de uma sala")
            print("8 - Sair de uma sala")
            print("0 - Voltar ao menu principal")
            op_sala = input("Escolha: ")

            if op_sala == "1":
                self.listar_salas()
            elif op_sala == "2":
                room_name = input("Digite o nome da nova sala: ")
                self.criar_sala(room_name)
            elif op_sala == "3":
                room_name = input("Digite o nome da sala para entrar no chat: ")
                self.iniciar_chat_de_sala(room_name)
            elif op_sala == "4":
                room_name = input("Nome da sua sala: ")
                target_user = input("Nome do usuário a convidar: ")
                self.convidar_para_sala(room_name, target_user)
            elif op_sala == "5":
                room_name = input("Nome da sua sala: ")
                target_user = input("Nome do usuário a remover: ")
                self.expulsar_da_sala(room_name, target_user)
            elif op_sala == "6":
                room_name = input("Nome da sala a ser apagada: ")
                self.apagar_sala(room_name)
            elif op_sala == "7":
                room_name = input("Nome da sala para ver os membros: ")
                self.listar_membros_sala(room_name)
            elif op_sala == "8":
                room_name = input("Nome da sala da qual deseja sair: ")
                self.sair_da_sala(room_name)
            elif op_sala == "0":
                break
            else:
                print("Opção inválida.")
            input("\nPressione Enter para continuar...")
            os.system('cls' if os.name == 'nt' else 'clear')
    
    def main_loop(self):
        """Loop principal de interação com o usuário."""
        #os.system('cls' if os.name == 'nt' else 'clear')
        while True:
            if not self.username:
                print("--- BEM-VINDO ---")
                print("1 - Registrar\n2 - Login\n3 - Sair")
                op = input("Escolha: ")

                if op == "3": break
                
                usuario = input("Usuário: ")
                senha = input("Senha: ")
                req = {"op": op, "usuario": usuario, "senha": senha}
                if op == "2" or op == "1":
                    req["p2p_port"] = self.p2p_port

                response = self.send_to_tracker(req)
                if response and response.get("aprovado"):
                    self.username = usuario
                    self.is_logged_in = True
                    heartbeat_thread = threading.Thread(target=self._send_heartbeat, daemon=True)
                    heartbeat_thread.start()
                    
                    self.my_files_db_path = f"files_{self.username}.json"
                    
                    self.my_shared_files = self._carregar_meus_arquivos()
                    print("Verificando por mensagens offline...")
                    offline_msgs_response = self.send_to_tracker({"op": "get_my_messages"})
                    if offline_msgs_response and offline_msgs_response.get("dados"):
                        mensagens = offline_msgs_response["dados"]
                        print(f"Você recebeu {len(mensagens)} mensagens enquanto estava offline:")
                        for msg in mensagens:
                            sender = msg['from']
                            content = msg['content']
                            timestamp = msg['timestamp']
                            print(f"[{timestamp}] [Mensagem de {sender}]: {content}")
                            self._salvar_historico_chat(sender, f"[{timestamp}] {sender}: {content}")
                    print(f"Metadados de '{self.username}' carregados de '{self.my_files_db_path}'.")
                    os.system('cls' if os.name == 'nt' else 'clear')

                elif response:
                    print(f"Erro: {response.get('texto')}")
                    input("\nPressione Enter para continuar...")
                    os.system('cls' if os.name == 'nt' else 'clear')
                else:
                    break
            else:
                print(f"\n--- Olá, {self.username}! (Porta P2P: {self.p2p_port}) ---")
                print("1 - Adicionar arquivo para compartilhar")
                print("2 - Baixar arquivo")
                print("3 - Listar arquivos no tracker")
                print("4 - Conversar 1-1")
                print("5 - Gerenciar Salas de Chat")
                print("6 - Sair (Logout)")
                op_p2p = input("Escolha: ")
                
                if op_p2p == "1":
                    filepath = input("Digite o caminho completo do arquivo: ")
                    self.adicionar_arquivo_para_compartilhar(filepath)
                
                elif op_p2p == "2":
                    filename = input("Nome do arquivo que deseja baixar: ")
                    self.download_file_sequencial(filename)
                    #self.download_file(filename)

                elif op_p2p == "3":
                    response = self.send_to_tracker({"op": "listar"})
                    if response: print(f"\nArquivos no Tracker:\n{response.get('texto')}")
                elif op_p2p == "4":
                    target_user = input("Digite o nome do usuário para conversar: ")
                    self.iniciar_chat(target_user)
                
                elif op_p2p == "5":
                    self._menu_salas()

                elif op_p2p == "6":
                    self._salvar_meus_arquivos()
                    self.send_to_tracker({"op": "sair"})
                    self.username, self.my_files_db_path, self.my_shared_files = "", None, {}
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.is_logged_in = False
                    break
                
                input("\nPressione Enter para continuar...")

    def start(self):
        """Inicia o peer, o servidor P2P e o cliente."""
        server_thread = threading.Thread(target=self.start_p2p_server)
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(0.1)

        if self.tracker_socket.connect_ex((self.tracker_host, self.tracker_port)) == 0:
            print("Conectado ao Tracker.")
            try:
                self.main_loop()
            except (KeyboardInterrupt, EOFError):
                print("\nEncerrando o peer...")
        else:
            print("Erro: Não foi possível conectar ao Tracker.")
            
        self.p2p_server_socket.close()
        self.tracker_socket.close()
        print("Peer finalizado.")

if __name__ == "__main__":
    peer = Peer()
    peer.start()