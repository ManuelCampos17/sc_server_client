import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class UtilsClient {

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

    // funcao para enviar o teste do ficheiro executável IoTDevice para o servidor
    public static String exeCliTest(ObjectOutputStream out, ObjectInputStream in) {
        try {
            // O cliente envia o nome e o tamanho do ficheiro executável IoTDevice (.class)
            byte[] nonce = (byte[]) in.readObject();

            String flName = "IoTDevice.class";
            File f = new File(flName);
            int flSize = (int) f.length();

            FileInputStream fis = new FileInputStream(f);
            BufferedInputStream bis = new BufferedInputStream(fis);
            byte[] bytesBuffer = new byte[flSize];
            long bytesRd = bis.read(bytesBuffer, 0, bytesBuffer.length);

            // Concatenar o nonce o conteudo do ficheiro
            byte[] concatNonceFl = new byte[nonce.length + bytesBuffer.length];
            System.arraycopy(nonce, 0, concatNonceFl, 0, nonce.length);
            System.arraycopy(bytesBuffer, 0, concatNonceFl, nonce.length, bytesBuffer.length);

            // Enviar o nome e o tamanho do ficheiro para o servidor
            System.out.println("File Verification: " + flName + ":" + bytesRd + " sent to server!");
            bis.close();

            // calcular hash SHA256 de concatNameSize
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(concatNonceFl);

            // Enviar o hash para o servidor
            out.writeObject(hash);
            out.flush();
            
            // Receber a resposta do servidor
            String srvResponse = (String) in.readObject();

            return srvResponse;
            
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }

    public static SecretKey generateDomainKey(String password, byte[] salt, int iter) {
        SecretKey sk = null;

        try {
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iter, 128);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            sk = kf.generateSecret(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return sk;
    }
    
}
