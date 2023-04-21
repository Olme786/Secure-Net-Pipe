import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    SecretKey secretKey;
    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {        
       KeyGenerator generator = KeyGenerator.getInstance("AES");
       generator.init(length);
       secretKey=generator.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) throws NoSuchAlgorithmException  {        
        SecretKeySpec secret= new SecretKeySpec(keybytes, "AES");
        secretKey = secret;
    }
    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return this.secretKey.getEncoded();
    }
}

