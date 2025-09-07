from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, UTC
import random
import my_pb2
import output_pb2
import json
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning
import time
from protobuf_decoder.protobuf_decoder import Parser
from google.protobuf.json_format import MessageToDict, ParseDict
import app_pb2

app = Flask(__name__)
from requests.exceptions import RequestException
# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

KEY_VALIDATION_URL = "https://scvirtual.alphi.media/botsistem/sendlike/expire_key.json"

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Init colorama
init(autoreset=True)

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})
def fetch_attversion():
    url = "https://pt.textbin.net/raw/alrhw5dehl"  # Link com JSON simples

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        def buscar_attversion(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k == "attversion":
                        return v
                    resultado = buscar_attversion(v)
                    if resultado is not None:
                        return resultado
            elif isinstance(d, list):
                for item in d:
                    resultado = buscar_attversion(item)
                    if resultado is not None:
                        return resultado
            return None
        
        attversion = buscar_attversion(data)
        if attversion is not None:
            print(f"attversion: {attversion}")
            return attversion
        else:
            print("Parâmetro 'attversion' não encontrado.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
    except ValueError:
        print("Erro ao decodificar o JSON.")


def get_token(password, uid, max_retries=3):
    """
    Obtém token de autenticação da API Garena com proteção contra rate limiting.
    
    Args:
        password (str): Senha/Token de acesso
        uid (str/int): ID do usuário
        max_retries (int): Número máximo de tentativas em caso de erro
        
    Returns:
        dict: Dicionário com token e open_id em caso de sucesso, None em caso de falha
    """
    # Configurações da requisição
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }

    # Tentativas com backoff exponencial
    for attempt in range(max_retries):
        try:
            # Delay progressivo entre tentativas
            if attempt > 0:
                wait_time = min((2 ** attempt) + random.uniform(0, 1), 10)  # Backoff exponencial com jitter
                print(f"Tentativa {attempt + 1}/{max_retries}. Aguardando {wait_time:.2f} segundos...")
                time.sleep(wait_time)

            # Faz a requisição
            res = requests.post(url, headers=headers, data=data, timeout=15)
            
            # Trata resposta
            if res.status_code == 200:
                token_json = res.json()
                if "access_token" in token_json and "open_id" in token_json:
                    return token_json
                else:
                    print("Resposta inválida: Token ou OpenID ausente")
                    continue
            
            # Trata rate limiting (429)
            elif res.status_code == 429:
                retry_after = res.headers.get('Retry-After', 5)  # Tenta obter tempo de espera do header
                print(f"Rate limit atingido. Servidor pede para esperar {retry_after} segundos.")
                time.sleep(float(retry_after))
                continue
            
            # Outros erros HTTP
            else:
                print(f"Erro HTTP {res.status_code}: {res.text}")
                continue

        except RequestException as e:
            print(f"Erro na requisição (tentativa {attempt + 1}): {str(e)}")
            continue
        
        except ValueError as e:
            print(f"Erro ao decodificar JSON (tentativa {attempt + 1}): {str(e)}")
            continue

    print(f"Falha após {max_retries} tentativas.")
    return None

def get_single_response():
    uid = '3860311887'
    password = '9A58A1429733E08B1D5E7E91FAE9B477CA6B54294F2ED1EFAA0F4672DB2B1D71'

    if not uid or not password:
        return "Error: Both UID and Password are required"

    token_data = get_token(password, uid)
    if not token_data:
        return "Error: Wrong UID or Password. Please check and try again."
    versionob = fetch_attversion()
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': f'{versionob}'
        }

        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            response_dict = parse_response(str(example_msg))

            token = response_dict.get("token")
            if token:
                return token  # 🔥 Retorna apenas o token puro
            else:
                return "Error: Token not found in response"
        else:
            return f"Error: HTTP {response.status_code} - {response.reason}"

    except Exception as e:
        return f"Error: {str(e)}"




def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

# GET JWT
def load_tokens():
    try:
        # Link direto para o JSON BR
        url = "https://scvirtual.alphi.media/botsistem/sendlike/tokenbr.json"
        
        response = requests.get(url)
        response.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        
        tokens_data = response.json()  # Converte para lista de dicionários
        
        # Extrai apenas os valores dos tokens para uma lista
        tokens_list = [item["token"] for item in tokens_data if "token" in item]
        
        # Seleciona um token aleatório se houver tokens disponíveis
        if tokens_list:
            return random.choice(tokens_list)
        return None

    except Exception as e:
        print(f"Error loading tokens: {e}")  # Mensagem de erro sem server_name
        return None
        
#DONT EDIT
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        
        if result.wire_type == "varint":
            field_data['data'] = result.data
        elif result.wire_type == "string":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data['data'] = parse_results(result.data.results)
        
        # Sempre adiciona como lista para campos repetidos
        if result.field in result_dict:
            if not isinstance(result_dict[result.field], list):
                # Se não for lista ainda, transforma o valor existente em lista
                result_dict[result.field] = [result_dict[result.field]]
            # Adiciona o novo valor à lista
            result_dict[result.field].append(field_data)
        else:
            # Para o primeiro valor, armazena diretamente (será convertido para lista se repetir)
            result_dict[result.field] = field_data
    
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)
def transform_json(input_json):
    output = {
        "Credit": "@scvirtual",
        "Region": "BR",
        "events": []
    }

    # Dicionário temporário para agrupar eventos pelo título
    events_by_title = {}

    # Processa eventos da Seção "1" (eventos normais)
    if "1" in input_json and "data" in input_json["1"]:
        if "1" in input_json["1"]["data"]:
            for item in input_json["1"]["data"]["1"]:
                if "data" not in item:
                    continue

                data = item["data"]

                # Verifica se a região é BR
                if "12" not in data or data["12"].get("data") != "BR":
                    continue

                # Extrai os dados básicos do evento
                title = data.get("3", {}).get("data", "")
                description = data.get("9", {}).get("data", "")
                image = data.get("5", {}).get("data", "")
                link = data.get("20", {}).get("data", data.get("8", {}).get("data", ""))

                # Pula se não tiver título
                if not title:
                    continue

                # Converte os timestamps para datas
                start_timestamp = data.get("10", {}).get("data") if "10" in data and data["10"]["wire_type"] == "varint" else None
                end_timestamp = data.get("11", {}).get("data") if "11" in data and data["11"]["wire_type"] == "varint" else None

                # Se o título já existe no dicionário, mescla as datas
                if title in events_by_title:
                    existing_event = events_by_title[title]

                    if start_timestamp and (existing_event["start_timestamp"] is None or start_timestamp < existing_event["start_timestamp"]):
                        existing_event["start_timestamp"] = start_timestamp

                    if end_timestamp and (existing_event["end_timestamp"] is None or end_timestamp > existing_event["end_timestamp"]):
                        existing_event["end_timestamp"] = end_timestamp

                    if not existing_event["description"] and description:
                        existing_event["description"] = description
                    if not existing_event["link"] and link:
                        existing_event["link"] = link
                    if not existing_event["image"] and image:
                        existing_event["image"] = image
                else:
                    events_by_title[title] = {
                        "title": title,
                        "start_timestamp": start_timestamp,
                        "end_timestamp": end_timestamp,
                        "description": description,
                        "link": link,
                        "image": image
                    }

    # Processa eventos da Seção "2" (promoções)
    if "2" in input_json and "data" in input_json["2"]:
        if "1" in input_json["2"]["data"]:
            for item in input_json["2"]["data"]["1"]:
                if "data" not in item:
                    continue

                data = item["data"]

                # Verifica se a região é BR
                if "1" not in data or data["1"].get("data") != "BR":
                    continue

                # Extrai os dados da promoção (tratando como um evento normal)
                title = data.get("4", {}).get("data", "")
                image = data.get("14", {}).get("data", "")
                start_timestamp = data.get("6", {}).get("data") if "6" in data and data["6"]["wire_type"] == "varint" else None
                end_timestamp = data.get("7", {}).get("data") if "7" in data and data["7"]["wire_type"] == "varint" else None

                # Se for uma promoção de diamantes, ajusta o título para ficar mais amigável
                if "[REVENUE]" in title:
                    title = title.replace("[REVENUE]", "").strip()
                elif "[PRODUCT]" in title:
                    title = title.replace("[PRODUCT]", "").strip()

                if not title:
                    continue

                # Se o título já existe, mescla (caso contrário, adiciona como novo evento)
                if title in events_by_title:
                    existing_event = events_by_title[title]

                    if start_timestamp and (existing_event["start_timestamp"] is None or start_timestamp < existing_event["start_timestamp"]):
                        existing_event["start_timestamp"] = start_timestamp

                    if end_timestamp and (existing_event["end_timestamp"] is None or end_timestamp > existing_event["end_timestamp"]):
                        existing_event["end_timestamp"] = end_timestamp

                    if not existing_event["image"] and image:
                        existing_event["image"] = image
                else:
                    events_by_title[title] = {
                        "title": title,
                        "start_timestamp": start_timestamp,
                        "end_timestamp": end_timestamp,
                        "description": "",  # Promoções geralmente não têm descrição
                        "link": "",  # Promoções geralmente não têm link externo
                        "image": image
                    }

    # Agora processa todos os eventos (Seção 1 + Seção 2) para criar a saída final
    now = datetime.now().timestamp()

    for title, event_data in events_by_title.items():
        # Formata as datas
        start = datetime.utcfromtimestamp(event_data["start_timestamp"]).strftime('%Y-%m-%d %H:%M:%S') if event_data["start_timestamp"] else ""
        end = datetime.utcfromtimestamp(event_data["end_timestamp"]).strftime('%Y-%m-%d %H:%M:%S') if event_data["end_timestamp"] else ""

        # Determina o status
        status = "Por vir"
        if event_data["start_timestamp"] and event_data["end_timestamp"]:
            if now >= event_data["start_timestamp"] and now <= event_data["end_timestamp"]:
                status = "Ativo"
            elif now > event_data["end_timestamp"]:
                status = "Encerrado"

        output["events"].append({
            "Tittle": title,
            "start": start,
            "end": end,
            "description": event_data["description"],
            "source": event_data["image"],
            "link": event_data["link"],
            "status": status
        })

    # Ordena os eventos por data de início
    output["events"].sort(
        key=lambda x: datetime.strptime(x["start"], '%Y-%m-%d %H:%M:%S') if x["start"] else datetime.min,
        reverse=True
    )

    return output
def is_valid_key(user_key):
    """Verifica se a key é válida ou expirada no JSON remoto"""
    try:
        # Força atualização do cache
        headers = {'Cache-Control': 'no-cache', 'Pragma': 'no-cache'}
        response = requests.get(KEY_VALIDATION_URL, headers=headers)

        keys_data = response.json()

        for key_info in keys_data.get("keys", []):
            
            if key_info["key"].strip() == user_key.strip():
                expiration_time = int(key_info["expires"])
                current_time = int(datetime.now(UTC).timestamp())
              
                return current_time < expiration_time

        return False

    except Exception as e:
        return False

def parse_protobuf_data(binary_data):
    """Parse os dados binários diretamente para o protobuf"""
    response = app_pb2.EventResponse()
    response.ParseFromString(binary_data)
    return response

def transform_protobuf_to_output(event_response):
    """Transforma a mensagem protobuf para o formato de saída"""
    output = app_pb2.FinalOutput()
    output.credit = "@scvirtual"
    output.region = "BR"
    
    now = datetime.now().timestamp()
    
    if event_response.HasField('event_group'):
        for item in event_response.event_group.items:
            if not item.data.region or item.data.region != "BR":
                continue
                
            if not item.data.title:
                continue
                
            # Cria evento transformado
            transformed_event = output.events.add()
            transformed_event.title = item.data.title
            transformed_event.source = item.data.source if item.data.source else ""
            
            # Processa tempos
            if item.data.start_time:
                transformed_event.start = datetime.utcfromtimestamp(item.data.start_time).strftime('%Y-%m-%d %H:%M:%S')
            
            if item.data.end_time:
                transformed_event.end = datetime.utcfromtimestamp(item.data.end_time).strftime('%Y-%m-%d %H:%M:%S')
            
            # Determina status
            if item.data.start_time and item.data.end_time:
                if now >= item.data.start_time and now <= item.data.end_time:
                    transformed_event.status = "Ativo"
                elif now > item.data.end_time:
                    transformed_event.status = "Encerrado"
                else:
                    transformed_event.status = "Por vir"
            else:
                transformed_event.status = "Por vir"
    
    # Ordena eventos
    output.events.sort(key=lambda x: x.start if x.start else "", reverse=True)
    return output

@app.route('/get-events', methods=['GET'])
def get_player_info():
    try:
        user_key = request.args.get('key')

        # 🔑 Validação da chave
        if not is_valid_key(user_key):
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": "Chave inválida ou expirada",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 403

        # 🔑 Obter token JWT
        jwt_token = load_tokens()
        if not jwt_token:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": "Falha ao gerar token JWT",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # 📦 Versão e payload
        versionob = fetch_attversion()
        data_hex = "9223af2eab91b7a150d528f657731074"
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as e:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": f"Erro ao codificar dados: {str(e)}",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # 🔧 Headers
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': versionob,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive'
        }

        # 🚀 Request
        try:
            endpoint = "https://client.us.freefiremobile.com/LoginGetSplash"
            response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        except requests.exceptions.RequestException as e:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": f"Erro na requisição: {str(e)}",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # ⚠️ Verificação do status HTTP
        if response.status_code != 200:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": f"API retornou status {response.status_code}",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), response.status_code

        # 🎯 Tenta protobuf primeiro
        try:
            event_response = app_pb2.EventResponse()
            event_response.ParseFromString(response.content)
            final_output = transform_protobuf_to_output(event_response)
            output_dict = MessageToDict(final_output)
            return jsonify(output_dict)

        except Exception as protobuf_error:
            # 🔄 Se protobuf falhar, tenta via hex
            try:
                hex_response = binascii.hexlify(response.content).decode('utf-8')
                json_result = get_available_room(hex_response)
                parsed_data = json.loads(json_result)
                transformed_data = transform_json(parsed_data)
                return jsonify(transformed_data)
            except Exception as hex_error:
                return jsonify({
                    "credits": "TEAM-AKIRU",
                    "message": "Erro ao processar resposta",
                    "status": "error",
                    "raw_response": binascii.hexlify(response.content).decode('utf-8'),
                    "protobuf_error": str(protobuf_error),
                    "hex_error": str(hex_error),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }), 500

    except Exception as e:
        # ⚠️ Aqui havia bug: "response" pode não existir no escopo do erro
        return jsonify({
            "credits": "TEAM-AKIRU",
            "message": f"Erro inesperado: {str(e)}",
            "status": "error",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500
if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000, debug=True)
