import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
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

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
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
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main(String[] args) {
        parseArgs(args);
        ServerSocket serverSocket = null;
        HandshakeCrypto privatekey = null;
        HandshakeCertificate userCert = null;
        HandshakeCertificate cacert = null;

        // WE CHECK THE PARAMETERS

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
        String key = arguments.get("key");
        
        try {
            
            FileInputStream keyInputStream = new FileInputStream(key);
            
            byte[] keybytes = keyInputStream.readAllBytes();
            
            privatekey = new HandshakeCrypto(keybytes);
            
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {

            System.out.println(e);
            System.exit(1);
        }
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }

        // WE START THE EXCHANGE OF CERTIFICATES

        HandshakeMessage fromClient = null;
        try {
            fromClient = HandshakeMessage.recv(socket);
        } catch (ClassNotFoundException | IOException e) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
          
           
        }
        HandshakeCertificate clientCertificate = null;
        byte[] iv = null;
        byte[] sessionkeys = null;
        HandshakeMessage serverHello= null;
        if (fromClient.getType().equals(HandshakeMessage.MessageType.CLIENTHELLO)) {
            String encodedCertificate = fromClient.getParameter("Certificate");
            byte[] bytecertificate = Base64.getDecoder().decode(encodedCertificate);

            String usercertstring=  Base64.getEncoder().encodeToString(bytecertificate);
            System.out.println("Receive handshake message:");
            System.out.println("    MessageType = " + fromClient.getType());
            System.out.println("    Certificate = "+ usercertstring.substring(0, 30) +" ... "+ usercertstring.substring(usercertstring.length()-30, usercertstring.length()) +" ("+usercertstring.length()+" bytes)");
        
        
        
        
            try {
                clientCertificate = new HandshakeCertificate(bytecertificate);
            } catch (CertificateException e) {
                System.out.println("That is not a certificate\n");
                System.exit(1);
            }
            try {
                clientCertificate.verify(cacert);
            } catch (Exception e) {
                System.out.println("The certificate received from the client cannot be openen with the CA certificate");
                System.exit(1);
            }

            // WE SEND OUR CERTIFICATE

           serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
            try {
                serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(userCert.getBytes()));
                System.out.println("Send handshake message");
            System.out.println(   "    MessageType = SERVERHELLO");
            String enviar =  Base64.getEncoder().encodeToString(userCert.getBytes());
            System.out.println(   "    Certificate = "+enviar.substring(0,30)+" ... "+enviar.substring(enviar.length()-30, enviar.length())+" ("+enviar.length()+" bytes)");

            } catch (CertificateEncodingException e1) {
                System.out.println("This is not a certificate");
                System.exit(1);
            }
            
            try {
                serverHello.send(socket);
            } catch (IOException e) {
                System.out.printf("Error accepting connection on port %d\n", port);
                System.exit(1);
            }
        }

        // WE VERIFY THE SESSION
        HandshakeMessage fromSession = null;
        try {
            fromSession = HandshakeMessage.recv(socket);
        } catch (ClassNotFoundException | IOException e) {
            System.out.printf("Problem with the socket in the session");
            System.exit(1);
        }
        SessionKey sessionkey = null;
        SessionCipher cipher=null;
        if (fromSession.getType().equals(HandshakeMessage.MessageType.SESSION)) {
            String encodedsession = fromSession.getParameter("SessionKey");
            String encodediv = fromSession.getParameter("SessionIV");
            byte[] byteiv = Base64.getDecoder().decode(encodediv);
            byte[] bytekey = Base64.getDecoder().decode(encodedsession);
            
            try {
                sessionkeys = privatekey.decrypt(bytekey);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                System.out.printf("Is encrypted with another public key");
                System.exit(1);
            }
            try {
                iv = privatekey.decrypt(byteiv);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                System.out.printf("Is encrypted with another public key");
                System.exit(1);
            }
            
            try {
                sessionkey = new SessionKey(sessionkeys);
            } catch (NoSuchAlgorithmException e) {
                System.out.printf("We cant decrypt the key with aes algorithm");
                System.exit(1);
            }
            try {
                cipher = new SessionCipher(sessionkey, iv);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                    | InvalidAlgorithmParameterException e3) {
                        System.out.printf("Error with the sessioncipher");
                        System.exit(1);
            }
            System.out.println("Receive handshake message");
            System.out.println("    MessageTYPE = SESSION");
            System.out.println("    SessionKey = "+ encodedsession.substring(0,30)+" ... "+encodedsession.substring(encodedsession.length()-30, encodedsession.length()) +" ("+ encodedsession.length()+" bytes)");
            System.out.println("    SessionIV = "+ encodediv.substring(0,30)+" ... "+encodediv.substring(encodediv.length()-30, encodediv.length()) +" ("+ encodediv.length()+" bytes)");
            String ivString =  Base64.getEncoder().encodeToString(iv);
            String keystring = Base64.getEncoder().encodeToString(sessionkeys);
            System.out.println("    DecryptedSessionIV in hex ("+ ivString.length()+"bytes): "+ivString);
            System.out.println("    DecryptedSessionKey in hex ("+ keystring.length()+"bytes): "+keystring);
            // Create the digest

            HandshakeDigest hash = null;
            try {
                hash = new HandshakeDigest();
            } catch (NoSuchAlgorithmException e) {
                System.out.printf("Problem with the digest");
                System.exit(1);
            }
            
                try {
                    hash.update(serverHello.getBytes());
                } catch (IOException e3) {
                    System.out.print(e3);
                System.exit(1);
                }
            
            byte[] digest = hash.digest();
            String data = DateTimeFormatter.ofPattern("yyy-MM-dd").format(LocalDateTime.now())+" "+DateTimeFormatter.ofLocalizedTime(FormatStyle.MEDIUM).format(LocalDateTime.now());
            byte[] b = data.getBytes(StandardCharsets.UTF_8);
            String utf8string = new String(b);
            byte[] time = null;
            byte[] digest1 = null;
            // Encrypt the digest and timestamp and then we convert them to base 64
            try {
                digest1 = privatekey.encrypt(digest);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e2) {
                System.out.printf("Problem with the encryption in the digest");
                System.exit(1);
            }
            try {
                time = privatekey.encrypt(utf8string.getBytes());
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e1) {
                System.out.printf("Problem with encryption in the timestamp");
                System.exit(1);
            }

            String handshakedigest = Base64.getEncoder().encodeToString(digest1);
            String time1 = Base64.getEncoder().encodeToString(time);
            System.out.println("Send handshake message");
            System.out.println("    MessageType = SERVERFINISHED");
            System.out.println("    Signature = "+handshakedigest.substring(0,30)+" ... "+handshakedigest.substring(handshakedigest.length()-30, handshakedigest.length())+" ("+handshakedigest.length()+" bytes)");
            System.out.println("    TimeStamp = "+time1.substring(0,30)+" ... "+time1.substring(time1.length()-30, time1.length())+" ("+time1.length()+" bytes)");

            // We put the parameters and we send them
            HandshakeMessage serverfinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
            serverfinished.putParameter("TimeStamp", time1);
            serverfinished.putParameter("Signature", handshakedigest);
            try {
                serverfinished.send(socket);
            } catch (IOException e) {
                System.out.printf("Problem with the delivery of the serverfinished");
                System.exit(1);
            }
        }
        HandshakeMessage clientfinished = null;
        

        //We receive the client finished
        try {
            clientfinished = HandshakeMessage.recv(socket);
        } catch (ClassNotFoundException | IOException e) {
           System.out.println("There is a problem with the socket in the socket of the clientfinished");
            System.exit(1);
        }


        if (clientfinished.getType().equals(HandshakeMessage.MessageType.CLIENTFINISHED)) {

            String encodetimestamp = clientfinished.getParameter("TimeStamp");
            byte[] timestamp = Base64.getDecoder().decode(encodetimestamp);
            String encodedigest = clientfinished.getParameter("Signature");
            byte[] digest = Base64.getDecoder().decode(encodedigest);
            byte[] digestClient = null;
            HandshakeCrypto res = new HandshakeCrypto(clientCertificate);
            try {
                digestClient = res.decrypt(digest);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                System.out.println("Problem with decryption of the digest");
                System.exit(1);
            }
            byte[] timeClientByte = null;
            try {
                timeClientByte = res.decrypt(timestamp);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e) {
                System.out.println("Problem with decryption of the timestamp");
                System.exit(1);
            }
            String timeClient = new String(timeClientByte, StandardCharsets.UTF_8);

            // Let's verify that the digest is the correct one
            HandshakeDigest h = null;
            try {
                h = new HandshakeDigest();
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Problem with the creation of handshakedigest");
                System.exit(1);
            }
            try {
                h.update(fromClient.getBytes());
                h.update(fromSession.getBytes());
                
            } catch (IOException e1) {
                System.out.println(e1);
                System.exit(1);
            }
           
          
            byte[] hg = h.digest();
            if(!Arrays.equals(hg,digestClient)) {
                System.out.println(Arrays.toString(hg));
                System.out.println(Arrays.toString(digestClient));
                System.out.println("The digest is not the same");
                System.exit(1);

            }
            String data2 = DateTimeFormatter.ofPattern("yyy-MM-dd").format(LocalDateTime.now())+" "+DateTimeFormatter.ofLocalizedTime(FormatStyle.MEDIUM).format(LocalDateTime.now());
            byte[] b2 = data2.getBytes(StandardCharsets.UTF_8);
            String utf8string1 = new String(b2);
            if(!(utf8string1.equals(timeClient))) {
                System.out.println("The timestamp is not the same");
                System.exit(1);
            }

            System.out.println("Receive handshake message:");
            System.out.println("    MessageType = CLIENTFINISHED");
            System.out.println("    Signature = "+encodedigest.substring(0,30)+" ... "+encodedigest.substring(encodedigest.length()-30, encodedigest.length())+" ("+encodedigest.length()+" bytes)");
            System.out.println("    Timestamp = "+encodetimestamp.substring(0,30)+" ... "+encodetimestamp.substring(encodetimestamp.length()-30, encodetimestamp.length())+" ("+encodetimestamp.length()+" bytes)");
            //No se como comprobar el timestamp

        }
        SessionKey ke1y= null;
        try {
            ke1y = new SessionKey(sessionkeys);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Problem with the session key");
                System.exit(1);
        }
        SessionCipher s = null;

        try {
            s = new SessionCipher(ke1y,iv);

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException e) {
                    System.out.println(e);
                    System.exit(1);
        }
       

        try {
            Forwarder.forwardStreams(System.in,System.out,s.openDecryptedInputStream(socket.getInputStream()), s.openEncryptedOutputStream(socket.getOutputStream()), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
