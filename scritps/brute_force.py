import os
import sys
import ecdsa
import hashlib
import base58
import time
import logging
from multiprocessing import Pool, cpu_count

# Configuração de logging com codificação UTF-8
def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

# Definir o endereço Bitcoin fornecido
BITCOIN_ADDRESS = "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm"
VERSION = "1.0.0.0"
THREADS = 1
CHECKPOINT_FILE = "checkpoint.txt"

# Função para gerar a chave pública em formato compactado
def get_public_key_bytes(private_key_bytes):
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key

    # Obter a chave pública em formato compactado
    public_key_bytes = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    return public_key_bytes

# Função para gerar o endereço Bitcoin a partir de uma chave privada
def generate_bitcoin_address(private_key_bytes):
    public_key_bytes = get_public_key_bytes(private_key_bytes)

    # Calcular o hash SHA-256 do hash RIPEMD-160 da chave pública
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key_bytes).digest())
    hashed_public_key = ripemd160.digest()

    # Prefixar com 0x00 para mainnet ou 0x6f para testnet
    versioned_payload = b'\x00' + hashed_public_key

    # Calcular o checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

    # Concatenar versão e checksum
    binary_address = versioned_payload + checksum

    # Codificar para Base58
    bitcoin_address = base58.b58encode(binary_address)

    return bitcoin_address.decode('utf-8')

# Função para verificar uma chave privada em um processo separado
def check_private_key(private_key_value):
    try:
        # Converter o valor da chave privada para bytes
        private_key_bytes = private_key_value.to_bytes(32, byteorder='big')

        # Gerar o endereço Bitcoin a partir da chave privada gerada
        generated_address = generate_bitcoin_address(private_key_bytes)

        # Log das informações de checksum e chave privada testada
        logging.info(f"Tested private key: {private_key_bytes.hex()}, Generated address: {generated_address}")

        # Verificar se o endereço gerado corresponde ao endereço fornecido
        if generated_address == BITCOIN_ADDRESS:
            return private_key_bytes.hex()  # Retornar a chave privada como string hexadecimal
    except Exception as e:
        logging.error(f"Error during key verification: {str(e)}")
    return None

# Função para encontrar a chave privada correspondente ao endereço Bitcoin fornecido
def find_private_key(num_cores):
    setup_logging(log_file="brute_force.log")
    
    # Verificar se há um checkpoint anterior
    start_value = 1
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            try:
                start_value = int(f.read().strip(), 16)  # Lê o valor hexadecimal do checkpoint
                logging.info(f"Resuming from checkpoint: {start_value}")
            except ValueError:
                logging.warning("Invalid checkpoint file. Starting from the beginning.")
    
    start_time = time.time()
    logging.info(f"Brute Force Bitcoin Private Key Finder by Francis Santiago - v: {VERSION}")
    logging.info(f"Initiating brute force search to find the private key corresponding to the address {BITCOIN_ADDRESS}...")
    
    checkpoint_counter = 0
    with Pool(processes=num_cores) as pool:
        private_key_value = start_value
        while True:
            # Cria um intervalo de valores de chaves privadas para verificar em paralelo
            keys_to_check = list(range(private_key_value, private_key_value + num_cores))
            private_key_value += num_cores

            # Verifica as chaves privadas em paralelo
            results = pool.map(check_private_key, keys_to_check)
            
            # Salvar o checkpoint após cada bloco verificado
            try:
                with open(CHECKPOINT_FILE, 'w') as f:
                    f.write(str(format(private_key_value, 'x').zfill(64)))
                checkpoint_counter += 1
            except Exception as e:
                logging.error(f"Failed to save checkpoint: {str(e)}")
            
            # Verifica se alguma chave privada corresponde ao endereço
            for result in results:
                if result:
                    elapsed_time = time.time() - start_time
                    logging.info(f"Matching private key found: {result}")
                    logging.info(f"Total elapsed time: {elapsed_time:.2f} seconds")

                    # Calcular a próxima chave privada a verificar
                    next_start_value = format(private_key_value, 'x').zfill(64)  # Formato hexadecimal completo
                    logging.info(f"Next search will start from private key: {next_start_value}")
                    pool.terminate()
                    return result

            # Log do progresso a cada 10000 checkpoints salvos
            if checkpoint_counter == 10000:
                elapsed_time = time.time() - start_time
                logging.info(f"Private key attempt until {format(private_key_value, 'x').zfill(64)}, Elapsed time: {elapsed_time:.2f} seconds")
                checkpoint_counter = 0  # Reinicia o contador

if __name__ == "__main__":
    # Número de núcleos de CPU a serem utilizados (defina isso conforme necessário)
    num_cores = min(cpu_count(), THREADS)

    # Executar a busca por força bruta
    try:
        find_private_key(num_cores)
    except Exception as e:
        logging.error(f"Error during script execution: {str(e)}")
