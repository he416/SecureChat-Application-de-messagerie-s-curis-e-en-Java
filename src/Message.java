import java.io.Serializable;

public class Message implements Serializable {
    private static final long serialVersionUID = 1L;
    public String sender;
    public String encryptedText;
    public long timestamp;

    public Message(String sender, String encryptedText) {
        this.sender = sender;
        this.encryptedText = encryptedText;
        this.timestamp = System.currentTimeMillis();
    }
}
