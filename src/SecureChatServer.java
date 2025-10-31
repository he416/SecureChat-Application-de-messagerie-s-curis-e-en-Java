import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SecureChatServer {
    public static final int PORT = 5000;
    public static Set<ClientHandler> clients = Collections.synchronizedSet(new HashSet<>());
    public static PrivateKey privateKey;
    public static PublicKey publicKey;

    public static void main(String[] args) {
        try {
            KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            System.out.println("Clé RSA générée.");
            System.out.println("Serveur SecureChat lancé sur le port " + PORT);

            ServerSocket serverSocket = new ServerSocket(PORT);
            while (true) {
                Socket socket = serverSocket.accept();
                ClientHandler handler = new ClientHandler(socket);
                clients.add(handler);
                handler.start();
            }
        } catch (Exception e) {
            System.out.println("Erreur serveur : " + e.getMessage());
        }
    }
}
