import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class SecureChatClient {
    private String serverIp = "localhost";
    private int serverPort = 5000;
    private String pseudo;

    public SecureChatClient(String pseudo) {
        this.pseudo = pseudo;
    }

    public void start() {
        try (Socket socket = new Socket(serverIp, serverPort)) {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // 1) Envoi du pseudo
            out.writeObject(pseudo);
            out.flush();

            // 2) Réception clé publique RSA
            String pubBase64 = (String) in.readObject();
            byte[] pubBytes = Base64.getDecoder().decode(pubBase64);
            PublicKey serverPub = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pubBytes));

            // 3) Génération clé AES et envoi chiffré
            SecretKey aesKey = CryptoUtils.generateAESKey(128);
            String aesBase64 = CryptoUtils.keyToBase64(aesKey);
            String encAES = CryptoUtils.encryptRSA(aesBase64.getBytes("UTF-8"), serverPub);
            out.writeObject(encAES);
            out.flush();

            System.out.println("Connexion établie. Tu peux écrire maintenant !");

            // Thread pour réception
            Thread reader = new Thread(() -> {
                try {
                    while (true) {
                        String enc = (String) in.readObject();
                        String msg = CryptoUtils.decryptAES(enc, aesKey);
                        System.out.println(msg);
                    }
                } catch (Exception e) {
                    System.out.println("Déconnecté du serveur.");
                }
            });
            reader.setDaemon(true);
            reader.start();

            // Lecture console
            Scanner sc = new Scanner(System.in);
            while (true) {
                String line = sc.nextLine();
                if (line.equalsIgnoreCase("/quit")) break;
                String encMsg = CryptoUtils.encryptAES(line, aesKey);
                out.writeObject(encMsg);
                out.flush();
            }

            socket.close();
            System.out.println("Fermeture du client.");
        } catch (Exception e) {
            System.out.println("Erreur client : " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        String pseudo;
        if (args.length > 0) pseudo = String.join(" ", args);
        else {
            System.out.print("Pseudo : ");
            Scanner sc = new Scanner(System.in);
            pseudo = sc.nextLine();
        }
        new SecureChatClient(pseudo).start();
    }
}
