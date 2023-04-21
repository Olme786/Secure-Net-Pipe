import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {
    SessionKey llaves;
    byte[] iv;
    Cipher c;
    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        llaves=key;
        Cipher cifrado = Cipher.getInstance("AES/CTR/NoPadding");      
        cifrado.init(Cipher.ENCRYPT_MODE,  key.getSecretKey());
        iv=cifrado.getIV();
        c= cifrado;
    }   

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        llaves=key;
        iv=ivbytes;
        Cipher cifrado2 = Cipher.getInstance("AES/CTR/NoPadding"); 
        cifrado2.init(Cipher.ENCRYPT_MODE,key.getSecretKey() ,new IvParameterSpec(ivbytes));
        c=cifrado2;
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return this.llaves;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return this.iv;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        CipherOutputStream entrar = new CipherOutputStream(os,c);
        return entrar;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        Cipher cifrado2= null;
        try {
          cifrado2 = Cipher.getInstance("AES/CTR/NoPadding"); 
            cifrado2.init(Cipher.DECRYPT_MODE,llaves.getSecretKey() ,new IvParameterSpec(iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException |NoSuchPaddingException e) {
            System.out.println("Problem in session cipher");
            System.exit(1);
        }
        CipherInputStream salir = new CipherInputStream(inputstream, cifrado2);
        return salir;
    }
}
