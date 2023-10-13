import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


def receive_encrypted_message(client_socket):
    encrypted_blocks = []
    while True:
        # Receber tamanho do bloco
        block_size = int(client_socket.recv(4).decode())
        # Receber bloco criptografado
        block = client_socket.recv(block_size)
        if not block:
            break
        encrypted_blocks.append(block)
    return b''.join(encrypted_blocks)

def main():
    host = 'localhost'
    porta = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, porta))
    print("Cliente conectado!")

    # Receber chave pública do servidor
    key_size = int(client_socket.recv(4).decode())
    public_key_bytes = client_socket.recv(key_size)
    public_key = serialization.load_der_public_key(public_key_bytes, backend=default_backend())

    # Receber e descriptografar mensagem do servidor
    encrypted_message = receive_encrypted_message(client_socket)
    mensagem_descriptografada = public_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Servidor diz: " + mensagem_descriptografada.decode('utf-8'))

    client_socket.close()

if __name__ == "__main__":
    main()
