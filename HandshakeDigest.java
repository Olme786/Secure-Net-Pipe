import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    /*
     * Constructor -- initialise a digest for SHA-256
     */
    MessageDigest m;
    byte[] res;
    public HandshakeDigest() throws NoSuchAlgorithmException {
         m =MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        m.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return m.digest();
    }
};
