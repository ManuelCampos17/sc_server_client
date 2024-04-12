// Classe para colocar funções úteis que podem ser usadas em várias partes do código

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Random;
import java.util.Scanner;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Utils {
    
    // // Função para inicializar a conexão com o servidor
    // public static SSLServerSocket initializeServer(String keyStorePath, String keyStorePassword, int port) {
    //     SSLServerSocket socket = null;

    //     System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
    //     System.setProperty("javax.net.ssl.keyStore", keyStorePath);
    //     System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

    //     SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
    //     try {
    //         socket = (SSLServerSocket) factory.createServerSocket(port);
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }

    //     return socket;
    // }
    public static SSLServerSocket initializeServer(String keyStorePath, String keyStorePassword, int port){
        SSLServerSocket socket = null;
        try {
            // TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // Inicializa o contexto com a chave do servidor
            // Substitua "server_keystore.jks" e "password" pelos seus valores
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
    
            socket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(port);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;

    }

    

    // public static SSLSocket initializeClient(String trusStrorePath, String trustStorePassword, String serverAddress, int port){
    //     SSLSocket s = null;

    //     System.setProperty("javax.net.ssl.trustStore", trusStrorePath);
    //     System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

    //     try{
    //         SocketFactory sf = SSLSocketFactory.getDefault();
    //         s = (SSLSocket) sf.createSocket(serverAddress, port);
    //     }catch(Exception e){
    //         e.printStackTrace();
    //     }

    //     return s;        
    // }

    public static SSLSocket initializeClient(String trustStorePath, String trustStorePassword, String serverAddress, int port) {
        SSLSocket socket = null;
        try {
            // TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            // Load the truststore
            KeyStore trustStore = KeyStore.getInstance("JCEKS");
            trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
            
            // Initialize trust manager factory with the truststore
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            
            // Initialize SSL context with the trust managers
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
    
            // Create the SSLSocket using the SSLContext
            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(serverAddress, port);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    
        return socket;
    }

    public static String generateC2FA() {
        Random random = new Random();
        int randomNumber = random.nextInt(100000);
        String fiveDigits = String.format("%05d", randomNumber);

        return fiveDigits;
    }

    public static boolean assymCrypt(ObjectOutputStream out, String userId, ObjectInputStream in, KeyStore tstore, KeyStore kstore, char[] kstorepass) {
        try {
            out.writeObject(userId);
            out.flush();

            byte[] nonce = (byte[]) in.readObject();
            String regStatus = (String) in.readObject();

            // Tratar a resposta do servidor
            if (regStatus.equals("notregistered")) {
                System.out.println("Unknown user. Initiating registering process...");

                // Realizar o registro do usuário
                boolean regSucc = registerUser(userId, tstore, nonce, out, in, kstore, kstorepass);

                if (regSucc) {
                    System.out.println("Registered successfuly.");
                } else {
                    System.out.println("Registering error.");
                    return false;
                }
            }
            else 
            {
                PrivateKey privateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);

                //Assinar nonce
                Signature sign = Signature.getInstance("MD5withRSA");
                sign.initSign(privateKey);
                sign.update(nonce);

                out.writeObject(sign.sign());
                out.flush();

                String res = (String) in.readObject();

                if (res.equals("checkedvalid")) {
                    System.out.println("Auth successful.");
                }
                else 
                {
                    System.out.println("Auth error.");
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static boolean registerUser(String userId, KeyStore tstore, byte[] nonce, ObjectOutputStream out, ObjectInputStream in, KeyStore kstore, char[] kpass) throws Exception {
        try {
            PrivateKey privateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kpass);

            out.writeObject(nonce);
            out.flush();

            //Assinar nonce
            Signature sign = Signature.getInstance("MD5withRSA");
            sign.initSign(privateKey);
            sign.update(nonce);

            out.writeObject(sign.sign());
            out.flush();

            Certificate cert = kstore.getCertificate(userId.split("@")[0]);

            out.writeObject(cert);
            out.flush();

            String res = (String) in.readObject();

            if (res.equals("checkedvalid")) {
                return true;
            }
            else 
            {
                return false;
            }
            
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean emailConf(Scanner sc, ObjectOutputStream out, ObjectInputStream in, String userId, KeyStore tstore, KeyStore kstore, char[] kstorepass) {
        try {
            String emailCorrect = (String) in.readObject();

            while (emailCorrect.equals("no")) {
                System.out.println("Email invalido, insira um email valido: ");
                userId = sc.nextLine();

                out.writeObject(userId);
                out.flush();

                emailCorrect = (String) in.readObject();
            }
            System.out.println("Introduza o codigo enviado pelo servidor: ");
            String code = sc.nextLine();

            out.writeObject(code);
            out.flush();

            String codeRes = (String) in.readObject();
            System.out.println(codeRes);

            if (codeRes.equals("C2FA code incorrect.")) {
                System.out.println("Deseja tentar autenticar-se de novo? Yes/No:");
                String respTryAgain = sc.nextLine();

                if (respTryAgain.equals("No")) {
                    out.writeObject("notryagain");
                    out.flush();

                    sc.close();
                    return false;
                }
                else 
                {
                    out.writeObject("tryagain");
                    out.flush();

                    IoTDevice.twoFactorAuth(sc, out, userId, in, tstore, kstore, kstorepass);
                }
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
