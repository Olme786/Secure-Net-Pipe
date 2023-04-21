import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.*;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<hostusercert>");
        System.err.println(indent + "--cacert=<hostcacert>");
        System.err.println(indent + "--key=<hostkey>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "hostusercert");
        arguments.setArgumentSpec("cacert", "hostcacert");
        arguments.setArgumentSpec("key", "hostkey");
        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main(String[] args) throws CertificateEncodingException {
        Socket socket = null;
        HandshakeCertificate cacert = null;
        HandshakeCertificate userCert = null;
        HandshakeCrypto privatekey = null;
        HandshakeCrypto cripto= null;
        parseArgs(args);


        //We check the parameters



        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        String stringuserCert = arguments.get("usercert");
        try {
            FileInputStream instream = new FileInputStream(stringuserCert);
            userCert = new HandshakeCertificate(instream);
        } catch (CertificateException | IOException e) {
            System.out.println("There is an error with the name of the user certificate \n");
            System.exit(1);
        }
        String stringcacert = arguments.get("cacert");
        try {
            FileInputStream insca = new FileInputStream(stringcacert);
            cacert = new HandshakeCertificate(insca);
        } catch (CertificateException | IOException e) {
            System.out.println("There is an error with the name of the CA certificate \n");
            System.exit(1);
        }
        String key1 = arguments.get("key");
        try {
            FileInputStream keyInputStream = new FileInputStream(key1);
            byte[] keybytes = keyInputStream.readAllBytes();
            privatekey = new HandshakeCrypto(keybytes);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {

            System.out.println("There is a problem with the name of the key\n");
            System.exit(1);
        }

        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }



    //We start the exchange of certificates
        System.out.println("Send handshake message:");
        System.out.println("    MessageType = CLIENTHELLO");
        String usercertstring=  Base64.getEncoder().encodeToString(userCert.getBytes());
        System.out.println("    Certificate = "+ usercertstring.substring(0, 30) +" ... "+ usercertstring.substring(usercertstring.length()-30, usercertstring.length()) +" ("+ usercertstring.length()+" bytes)");

        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", Base64.getEncoder().encodeToString(userCert.getBytes()));
        try {
            clientHello.send(socket);
        } catch (IOException e) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }


        //We receive the certificate and we check it
        HandshakeMessage fromServer = null;
        try {
            fromServer = HandshakeMessage.recv(socket);
        } catch (ClassNotFoundException | IOException e) {
            System.out.println("There is a problem with the reception of the server's certificate\n");
            System.exit(1);
        }
        HandshakeCertificate serverCertificate = null;
        byte[] bytecertificate = null;
        SessionCipher s= null;
        SessionKey key = null;
        HandshakeMessage session =null;
        if (fromServer.getType().equals(HandshakeMessage.MessageType.SERVERHELLO)) {
            String encodedCertificate = fromServer.getParameter("Certificate");
            bytecertificate = Base64.getDecoder().decode(encodedCertificate);
            try {
                serverCertificate = new HandshakeCertificate(bytecertificate);
            } catch (CertificateException e) {
                System.out.println("That is not a certificate\n");
                System.exit(1);
            }
            try {
                serverCertificate.verify(cacert);
            } catch (Exception e) {
                System.out.println("The certificate received from the client cannot be openen with the CA certificate");
                System.exit(1);
            }
            System.out.println("Receive handshake message:");
            System.out.println("    MessageType=SERVERHELLO");
            System.out.println("    Certificate = "+ encodedCertificate.substring(0, 30) +" ... "+ encodedCertificate.substring(encodedCertificate.length()-30, encodedCertificate.length()) +" ("+ encodedCertificate.length()+" bytes)");
            
            //We start the cipher parameters



           session = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
           
            try {
                key = new SessionKey(128);
            } catch (NoSuchAlgorithmException e) {
                System.out.println("It doesnt exist that algorithm");
                System.exit(1);
            }
            
            try {
                s = new SessionCipher(key);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                System.out.println("There is a problem with the key or the algorithm");
                System.exit(1);
            }
            
            
            cripto = new HandshakeCrypto(serverCertificate);
            byte[] cipheriv= null;
            try {
                cipheriv = cripto.encrypt(s.getIVBytes());
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                        System.out.println("There is a problem with the step of encrypting the session ivs");
                        System.exit(1);
            }
            String iv = Base64.getEncoder().encodeToString(cipheriv);
            byte[] cipherkey= null;
            try {
                cipherkey = cripto.encrypt(key.getKeyBytes());
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                        System.out.println("There is a problem with the step of encrypting the session key");
                        System.exit(1);
                    }
            String keyencode =  Base64.getEncoder().encodeToString(cipherkey);
            System.out.println("Send handshake message");
            System.out.println("    MessageTYPE = SESSION");
            System.out.println("    SessionKey = "+ keyencode.substring(0,30)+" ... "+keyencode.substring(keyencode.length()-30, keyencode.length()) +" ("+ keyencode.length()+" bytes)");
            System.out.println("    SessionIV = "+ iv.substring(0,30)+" ... "+iv.substring(iv.length()-30, iv.length()) +" ("+ iv.length()+" bytes)");
            
            session.putParameter("SessionIV", iv);
            session.putParameter("SessionKey", keyencode);
            try {
                session.send(socket);
            } catch (IOException e) {
                System.out.println("There is a problem with delivery of the send of the socket session");
                        System.exit(1);
            }
        }

        //We receive the digest of the server

        HandshakeMessage serverfinished= null;
        try {
            serverfinished = HandshakeMessage.recv(socket);
        } catch (ClassNotFoundException | IOException e) {
            System.out.printf("Problem with the reception of the serverfinished");
            System.exit(1);
        }
        if(serverfinished.getType().equals(HandshakeMessage.MessageType.SERVERFINISHED)) {
            //We take the message and we decrypt it 
            String encodetimestamp = serverfinished.getParameter("TimeStamp");
            byte[] timestamp = Base64.getDecoder().decode(encodetimestamp);
            String encodedigest= serverfinished.getParameter("Signature");
            byte[] digest = Base64.getDecoder().decode(encodedigest);
            byte[] digestServer= null;
            try {
                digestServer = cripto.decrypt(digest);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                        System.out.println("Problem with decryption of the digest");
                        System.exit(1);
            }
            byte[] timeServerbyte=null;
            try {
                timeServerbyte = cripto.decrypt(timestamp);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                        System.out.println("Problem with decryption of the timestamp");
                        System.exit(1);
            }
            String timeServer = new String(timeServerbyte,StandardCharsets.UTF_8);

            //Let's verify that the digest is the correct one
            HandshakeDigest h = null;
            try {
                h = new HandshakeDigest();
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Problem with the creation of handshakedigest");
                        System.exit(1);
            }
            try {
                h.update(fromServer.getBytes());
            } catch (IOException e1) {
                System.out.println(e1);
                        System.exit(1);
            }
            byte[] comprobacionDigest = h.digest();
            if(!Arrays.equals(digestServer,comprobacionDigest)) {
                
                System.out.println(" The digest is not the same");
                System.exit(1);
            }
            String data2 = DateTimeFormatter.ofPattern("yyy-MM-dd").format(LocalDateTime.now())+" "+DateTimeFormatter.ofLocalizedTime(FormatStyle.MEDIUM).format(LocalDateTime.now());
            byte[] b2 = data2.getBytes(StandardCharsets.UTF_8);
            String utf8string1 = new String(b2);
            if(!(utf8string1.equals(timeServer))) {
                System.out.println(utf8string1);
                System.out.println(timeServer);
                System.out.println("The timestamp is not the same");
                System.exit(1);
            }

            //I dont know how to check the timestamp
            System.out.print("Receive handshake message:");
            System.out.println("    MessageType = SERVERFINISHED");
            System.out.println("    Signature = "+encodedigest.substring(0,30)+" ... "+encodedigest.substring(encodedigest.length()-30, encodedigest.length())+" ("+encodedigest.length()+" bytes)");
            System.out.println("    Timestamp = "+encodetimestamp.substring(0,30)+" ... "+encodetimestamp.substring(encodetimestamp.length()-30, encodetimestamp.length())+" ("+encodetimestamp.length()+" bytes)");



            //Create the digest and send it to the server
            HandshakeDigest client= null;
            try {
                client = new HandshakeDigest();
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Problem with the creation of handshakedigest");
                System.exit(1);
            }
           
            try {
                client.update(clientHello.getBytes());
                client.update(session.getBytes());
            } catch (IOException e1) {
                System.out.println(e1);
                System.exit(1);
            }
            
            byte[] clientdigest = client.digest();
            String data = DateTimeFormatter.ofPattern("yyy-MM-dd").format(LocalDateTime.now())+" "+DateTimeFormatter.ofLocalizedTime(FormatStyle.MEDIUM).format(LocalDateTime.now());
            byte[] b = data.getBytes(StandardCharsets.UTF_8);
            String utf8string = new String(b);
            
            //Encrypt the data
            byte[] encodetimestampclient = null;
            byte[] encodeclientdigest = null;
            try {
                encodeclientdigest = privatekey.encrypt(clientdigest);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                        System.out.println("Problem with the encryption of the digest");
                        System.exit(1);
            }     
            try {
                encodetimestampclient = privatekey.encrypt(utf8string.getBytes());
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                        System.out.println("Problem with the encryption of the timestamp");
                        System.exit(1);
            }
            String tim =Base64.getEncoder().encodeToString(encodetimestampclient);
            String dig=Base64.getEncoder().encodeToString(encodeclientdigest);
            
            //We send the messagae to the server
            HandshakeMessage clientfinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
            clientfinished.putParameter("Signature", dig);
            clientfinished.putParameter("TimeStamp", tim);
            System.out.print("Send handshake message:");
            System.out.println("    MessageType = CLIENTFINISHED");
            System.out.println("    Signature = "+dig.substring(0,30)+" ... "+dig.substring(dig.length()-30, dig.length())+" ("+dig.length()+" bytes)");
            System.out.println("    Timestamp = "+tim.substring(0,30)+" ... "+tim.substring(tim.length()-30, tim.length())+" ("+tim.length()+" bytes)");;
            try {
                clientfinished.send(socket);
            } catch (IOException e) {
                System.out.println("Problem with the socket of the clientfinished");
                System.exit(1);
            }

        
        
        
        }
        
        



        try {
            Forwarder.forwardStreams(System.in, System.out, s.openDecryptedInputStream(socket.getInputStream()), s.openEncryptedOutputStream(socket.getOutputStream()), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
