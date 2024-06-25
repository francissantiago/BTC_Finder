import ecdsa
import hashlib
import base58
import time

# Definir o endereço Bitcoin fornecido
BITCOIN_ADDRESS = "1PitScNLyp2HCygzadCh7FveTnfmpPbfp8"
VERSION = "1.0.0.0"

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

# Função para encontrar a chave privada correspondente ao endereço Bitcoin fornecido
def find_private_key():
    # Iniciar a busca a partir da chave privada conhecida
    private_key_value = 1
    start_time = time.time()

    print(f"Brute Force Bitcoin Private Key Finder by Francis Santiago - v: {VERSION}")
    print(f"Iniciando busca por força bruta para encontrar a chave privada correspondente ao endereço {BITCOIN_ADDRESS}...")
    
    try:
        while True:
            # Converter o valor da chave privada para bytes
            private_key_bytes = private_key_value.to_bytes(32, byteorder='big')

            # Gerar o endereço Bitcoin a partir da chave privada gerada
            generated_address = generate_bitcoin_address(private_key_bytes)

            # Log do progresso
            if private_key_value % 100000 == 0:
                elapsed_time = time.time() - start_time
                print(f"Tentativa de chave privada: {private_key_value}, Tempo decorrido: {elapsed_time:.2f} segundos")

            # Log das informações de checksum e chave privada testada
            print(f"Chave privada testada: {private_key_bytes.hex()}, Endereço gerado: {generated_address}")

            # Verificar se o endereço gerado corresponde ao endereço fornecido
            if generated_address == BITCOIN_ADDRESS:
                return private_key_bytes.hex()  # Retornar a chave privada como string hexadecimal

            # Incrementar para verificar a próxima chave privada
            private_key_value += 1

    except KeyboardInterrupt:
        print("\nBusca interrompida pelo usuário.")
    except Exception as e:
        print(f"Erro durante a busca: {str(e)}")

    print("Nenhuma chave privada correspondente encontrada dentro do intervalo.")

# Executar a busca por força bruta
try:
    private_key_hex = find_private_key()
    if private_key_hex:
        print(f"Chave privada correspondente encontrada: {private_key_hex}")
except Exception as e:
    print(f"Erro durante a execução do script: {str(e)}")
