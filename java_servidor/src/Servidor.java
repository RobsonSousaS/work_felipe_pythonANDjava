import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class Servidor {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Servidor esperando por conexoes...");

            // Gerar chaves
            KeyPair keyPair = generateKeys();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Cliente conectado!");

                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                // Enviar chave pública para o cliente (como bytes)
                byte[] publicKeyBytes = publicKey.getEncoded();
                out.println(publicKeyBytes.length); // Enviar tamanho da chave
                clientSocket.getOutputStream().write(publicKeyBytes); // Enviar chave pública

                // Criptografar e enviar mensagem para o cliente
                String mensagemParaCliente = "Mensagem confidencial do servidor";
                String mensagemCriptografadaParaCliente = encryptMessage(mensagemParaCliente, publicKey);
                sendEncryptedMessage(clientSocket, mensagemCriptografadaParaCliente);

                // Fechar conexão
                in.close();
                out.close();
                clientSocket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generateKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static String encryptMessage(String message, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void sendEncryptedMessage(Socket socket, String message) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        int blockSize = 32; // ou qualquer tamanho desejado para os blocos

        for (int i = 0; i < encryptedBytes.length; i += blockSize) {
            int endIndex = Math.min(i + blockSize, encryptedBytes.length);
            byte[] chunk = Arrays.copyOfRange(encryptedBytes, i, endIndex);
            socket.getOutputStream().write(chunk.length); // Enviar tamanho do bloco
            socket.getOutputStream().write(chunk); // Enviar bloco criptografado
        }
    }
}
