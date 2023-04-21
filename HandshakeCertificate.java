import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    X509Certificate cert;

    /*
     * Constructor to creat cate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) certFactory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certbytes);
        cert = (X509Certificate) certFactory.generateCertificate(in);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return this.cert.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, NoSuchProviderException {
        cert.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        String str = cert.toString();
        int begin_index = str.indexOf(',') + 5;
        str = str.substring(begin_index);
        int cn_end = str.indexOf(',');
        String res = str.substring(0, cn_end);
        return res;

    }

    /*
     * return email address of subject
     */
    public String getEmail() {

        String str = cert.toString();
        int begin_index = str.indexOf('=') + 1;
        str = str.substring(begin_index);
        int email_end = str.indexOf(',');
        String res = str.substring(0, email_end);
        return res;
    }
}
