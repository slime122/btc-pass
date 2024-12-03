# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import time
import logging
import os
from dotenv import load_dotenv
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes
)
from aiohttp import ClientSession, ClientTimeout
from typing import List
from eth_utils import is_address  # Para validação de endereços ETH

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações
OUTPUT_FILE = os.getenv('OUTPUT_FILE', 'carteiras_com_saldo.txt')
NUM_TASKS = int(os.getenv('NUM_TASKS', 2))  # Reduzido para 2 para evitar bloqueios
API_TIMEOUT = int(os.getenv('API_TIMEOUT', 10))
BALANCE_THRESHOLD_BTC = float(os.getenv('BALANCE_THRESHOLD_BTC', 0.00000001))  # 1 satoshi
BALANCE_THRESHOLD_ETH = float(os.getenv('BALANCE_THRESHOLD_ETH', 0.0001))  # 0.0001 ETH
PROXY = os.getenv('PROXY', None)  # Endereço do proxy HTTP

# Configurar logging
logging.basicConfig(
    level=logging.INFO,  # Ajustado para INFO; logs detalhados usarão DEBUG
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("script.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Criar um lock global para escrita no arquivo
file_lock = asyncio.Lock()

def carregar_proxy(proxy_str: str) -> str:
    if proxy_str:
        logger.info(f"Usando proxy: {proxy_str}")
        return proxy_str
    else:
        logger.warning("Nenhum proxy configurado. Continuando sem proxy.")
        return None

def validar_endereco_eth(endereco: str) -> bool:
    return is_address(endereco)

def gerar_endereco_btc(mnemonica: str) -> str:
    try:
        seed_bytes = Bip39SeedGenerator(mnemonica).Generate()
        bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip44_acc = bip44_mst.Purpose().Coin().Account(0)
        bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_addr = bip44_chg.AddressIndex(0)
        endereco = bip44_addr.PublicKey().ToAddress()
        # Assumimos que o endereço BTC gerado é válido
        return endereco
    except Exception as e:
        logger.debug(f"Erro ao gerar endereço BTC: {e}")
        return ""

def gerar_endereco_eth(mnemonica: str) -> str:
    try:
        seed_bytes = Bip39SeedGenerator(mnemonica).Generate()
        bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        bip44_acc = bip44_mst.Purpose().Coin().Account(0)
        bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_addr = bip44_chg.AddressIndex(0)
        endereco = bip44_addr.PublicKey().ToAddress()
        # Validar o endereço ETH
        if validar_endereco_eth(endereco):
            return endereco
        else:
            logger.debug(f"Endereço ETH inválido gerado: {endereco}")
            return ""
    except Exception as e:
        logger.debug(f"Erro ao gerar endereço ETH: {e}")
        return ""

async def verificar_saldo(endereco: str, currency: str, session: ClientSession, proxy: str, retry: int = 3, backoff_factor: float = 0.5) -> float:
    if currency.lower() == 'btc':
        apis = [
            f"https://api.blockchair.com/bitcoin/dashboards/address/{endereco}",
            f"https://api.blockcypher.com/v1/btc/main/addrs/{endereco}/balance",
            f"https://blockchain.info/rawaddr/{endereco}"
        ]
    elif currency.lower() == 'eth':
        apis = [
            f"https://api.blockchair.com/ethereum/dashboards/address/{endereco}",
            f"https://api.blockcypher.com/v1/eth/main/addrs/{endereco}/balance"
            # Adicione outras APIs de ETH aqui se necessário
        ]
    else:
        logger.error(f"Moeda não suportada: {currency}")
        return 0.0

    headers = {
        'User-Agent': 'Mozilla/5.0'
    }

    for url in apis:
        for attempt in range(1, retry + 1):
            try:
                async with session.get(url, headers=headers, proxy=proxy) as response:
                    if response.status == 200:
                        # Tenta decodificar a resposta como JSON
                        try:
                            data = await response.json()
                        except aiohttp.ContentTypeError:
                            logger.warning(f"Resposta da API {url} não está em formato JSON.")
                            break  # Tenta a próxima API

                        saldo = 0
                        if currency.lower() == 'btc':
                            if 'data' in data:
                                saldo = data['data'][endereco]['address']['balance'] / 1e8
                            elif 'balance' in data:
                                saldo = data['balance'] / 1e8
                            elif 'final_balance' in data:
                                saldo = data['final_balance'] / 1e8
                        elif currency.lower() == 'eth':
                            if 'data' in data:
                                saldo = data['data'][endereco]['address']['balance'] / 1e18
                            elif 'balance' in data:
                                saldo = data['balance'] / 1e18
                            elif 'final_balance' in data:
                                saldo = data['final_balance'] / 1e18

                        logger.info(f"Endereço {endereco} - Saldo: {saldo} {currency.upper()}")
                        return saldo
                    elif response.status in [429, 430]:
                        #logger.warning(f"Falha ao acessar API {url}. Status {response.status}. Tentando novamente após backoff...")
                        await asyncio.sleep(backoff_factor * (2 ** (attempt - 1)))
                    else:
                        #logger.warning(f"Falha ao acessar API {url}. Status {response.status}. Tentando próxima API...")
                        break  # Tenta a próxima API
            except asyncio.TimeoutError:
                #logger.warning(f"Timeout ao acessar API {url}. Tentando novamente após backoff...")
                await asyncio.sleep(backoff_factor * (2 ** (attempt - 1)))
            except Exception as e:
                #logger.error(f"Erro ao acessar API {url}: {e}. Tentando novamente após backoff...")
                await asyncio.sleep(backoff_factor * (2 ** (attempt - 1)))
        #logger.warning(f"Exaustão de tentativas para API {url}. Passando para a próxima API.")
    return 0.0

async def verificar_endereco_com_saldo(session: ClientSession, proxy: str, tarefa_id: int):
    while True:
        # Gerar uma mnemonic válida com 12 palavras
        mnemonica = Bip39MnemonicGenerator().FromWordsNumber(24).ToStr()
        endereco_btc = gerar_endereco_btc(mnemonica)
        endereco_eth = gerar_endereco_eth(mnemonica)
        if not endereco_btc or not endereco_eth:
            logger.debug(f"Tarefa {tarefa_id}: Mnemonic inválida. Gerando nova carteira...")
            continue
        logger.info(f"Tarefa {tarefa_id}: Gerando carteiras para BTC: {endereco_btc} e ETH: {endereco_eth} a partir da mnemonic.")

        saldo_btc = await verificar_saldo(endereco_btc, 'btc', session, proxy)
        saldo_eth = await verificar_saldo(endereco_eth, 'eth', session, proxy)

        # Verificar se qualquer um dos saldos atende o limiar
        if saldo_btc >= BALANCE_THRESHOLD_BTC or saldo_eth >= BALANCE_THRESHOLD_ETH:
            logger.info(f"Tarefa {tarefa_id}: Carteira encontrada! BTC: {saldo_btc} BTC, ETH: {saldo_eth} ETH")
            async with file_lock:
                with open(OUTPUT_FILE, 'a') as f:
                    f.write(
                        f"Combinacao: {mnemonica} - "
                        f"BTC Endereco: {endereco_btc} - Saldo: {saldo_btc} BTC - "
                        f"ETH Endereco: {endereco_eth} - Saldo: {saldo_eth} ETH\n"
                    )
            # Continua a execução para encontrar mais carteiras
        else:
            logger.debug(f"Tarefa {tarefa_id}: Carteiras BTC: {endereco_btc} com saldo {saldo_btc} BTC e ETH: {endereco_eth} com saldo {saldo_eth} ETH. Gerando novas carteiras...")

async def rodar():
    logger.info("Iniciando a busca por carteiras com saldo...")

    proxy = carregar_proxy(PROXY)

    timeout = ClientTimeout(total=API_TIMEOUT)
    connector = aiohttp.TCPConnector(limit_per_host=NUM_TASKS, ssl=False)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        start_time = time.time()

        for i in range(NUM_TASKS):
            task = asyncio.create_task(verificar_endereco_com_saldo(session, proxy, i + 1))
            tasks.append(task)

        await asyncio.gather(*tasks)

        end_time = time.time()
        logger.info(f"Tempo de execução: {end_time - start_time:.2f} segundos")

if __name__ == "__main__":
    try:
        asyncio.run(rodar())
    except KeyboardInterrupt:
        logger.info("Execução interrompida pelo usuário.")
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
