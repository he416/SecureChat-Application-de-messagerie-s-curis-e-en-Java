import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

public class ClientHandler extends Thread {
    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private SecretKey aesKey;
    private String pseudo;
    private boolean ready = false;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public boolean isReady() { return ready; }
    public SecretKey getAesKey() { return aesKey; }
    public String getPseudo() { return pseudo; }

    @Override
    public void run() {
        try {
            out = new ObjectOutputStream(socket.getOutputStream());
            in  = new ObjectInputStream(socket.getInputStream());

            // 1) Réception du pseudo
            pseudo = (String) in.readObject();
            System.out.println("Utilisateur connecté : " + pseudo);

            // 2) Envoi de la clé publique RSA du serveur
            byte[] pubBytes = SecureChatServer.publicKey.getEncoded();
            String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);
            out.writeObject(pubBase64);
            out.flush();

            // 3) Réception et déchiffrement de la clé AES
            String encAES = (String) in.readObject();
            byte[] decrypted = CryptoUtils.decryptRSA(encAES, SecureChatServer.privateKey);
            String aesBase64 = new String(decrypted, "UTF-8");
            aesKey = CryptoUtils.base64ToAESKey(aesBase64);
            ready = true;
            System.out.println("Clé AES établie pour " + pseudo);

            // 4) Diffusion du message de connexion
            broadcast("[Serveur] " + pseudo + " a rejoint la discussion.");

            // 5) Lecture des messages
            while (true) {
                String encMsg = (String) in.readObject();
                String plain = CryptoUtils.decryptAES(encMsg, aesKey);
                System.out.println(pseudo + " → " + plain);
                broadcast(pseudo + " : " + plain);
            }

        } catch (EOFException e) {
            System.out.println(pseudo + " s'est déconnecté.");
        } catch (Exception e) {
            System.out.println("Erreur (" + pseudo + "): " + e.getMessage());
        } finally {
            SecureChatServer.clients.remove(this);
            broadcast("[Serveur] " + pseudo + " a quitté la discussion.");
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    private void broadcast(String plainMessage) {
        for (ClientHandler c : SecureChatServer.clients) {
            if (c != this && c.isReady()) {
                try {
                    String enc = CryptoUtils.encryptAES(plainMessage, c.getAesKey());
                    c.out.writeObject(enc);
                    c.out.flush();
                } catch (Exception ignored) {}
            }
        }
    }
}
