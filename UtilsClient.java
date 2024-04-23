//Grupo 15: Tiago Almeida (58161), Manuel Campos (58166), Tiago Rocha (58242)

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class UtilsClient {

    public static SSLSocket initializeClient(String trustStorePath, String trustStorePassword, String serverAddress, int port) {
        SSLSocket socket = null;
        try {
            //TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            KeyStore trustStore = KeyStore.getInstance("JCEKS");
            trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
            
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
    
            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(serverAddress, port);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    
        return socket;
    }


    public static boolean assymCrypt(ObjectOutputStream out, String userId, ObjectInputStream in, KeyStore tstore, KeyStore kstore, char[] kstorepass) {
        try {
            //Enviar o userId para o server
            out.writeObject(userId);
            out.flush();

            byte[] nonce = (byte[]) in.readObject();
            String regStatus = (String) in.readObject();

            //Tratar a resposta do servidor
            if (regStatus.equals("notregistered")) {
                System.out.println("Unknown user. Initiating registering process...");

                //Registar o user
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
                //Ir buscar a private key do user a keystore
                PrivateKey privateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);

                //Assinar nonce
                Signature sign = Signature.getInstance("MD5withRSA");
                sign.initSign(privateKey);
                sign.update(nonce);

                //Enviar nonce assinado
                out.writeObject(sign.sign());
                out.flush();

                //Validado ou nao pelo server
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
            //Ir buscar a private key do user a keystore
            PrivateKey privateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kpass);

            //Enviar outra vez o nonce enviado pelo server
            out.writeObject(nonce);
            out.flush();

            //Assinar nonce
            Signature sign = Signature.getInstance("MD5withRSA");
            sign.initSign(privateKey);
            sign.update(nonce);

            //Enviar nonce assinado
            out.writeObject(sign.sign());
            out.flush();

            //Ir buscar o certificado do user
            Certificate cert = kstore.getCertificate(userId.split("@")[0]);

            //Enviar o certificado
            out.writeObject(cert);
            out.flush();

            //Validado ou nao pelo server
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
            //Server verifica se foi enviado um email valido (pre definimos como sendo os emails de nos os 3)
            String emailCorrect = (String) in.readObject();

            //Email tem de ser válido
            if (emailCorrect.equals("no")) {
                System.out.println("Email invalido!");
                return false;
            }

            //Ir ver ao email o codigo
            System.out.println("Introduza o codigo enviado pelo servidor: ");
            String code = sc.nextLine();

            //Enviar o codigo ao server
            out.writeObject(code);
            out.flush();

            //Server verifica o codigo
            String codeRes = (String) in.readObject();
            System.out.println(codeRes);

            //Se incorreto, e possivel o o user voltar a tentar a autenticacao desde o inicio do two factor
            if (codeRes.equals("C2FA code incorrect.")) {
                System.out.println("Deseja tentar autenticar-se de novo? Yes/No:");
                String respTryAgain = sc.nextLine();

                //Terminar ligacao se nao, se sim invocar outra vez a funcao de inicio
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

    //Funcao para enviar o teste do ficheiro executável IoTDevice para o servidor
    public static String exeCliTest(ObjectOutputStream out, ObjectInputStream in) {
        try {
            // O cliente envia o nome e o tamanho do ficheiro executável IoTDevice (.jar)
            byte[] nonce = (byte[]) in.readObject();

            String flName = "IoTDevice.jar";
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

    public static void genAndSendKey(Map<String, byte[]> saltsByDomain, Map<String, Integer> itersByDomain, String dom, String userId, String password, KeyStore tstore, SecureRandom rd, ObjectOutputStream out) {
        try {
            //Gerar key com password
            boolean firstAdd = false;

            byte[] salt = new byte[16];

            //Se ja tinhamos um salt associado ao domain, usar esse
            if (saltsByDomain.containsKey(dom)) {
                salt = saltsByDomain.get(dom);
            }
            else 
            {
                rd.nextBytes(salt);
                saltsByDomain.put(dom, salt);
                firstAdd = true;
            }

            int iter = rd.nextInt(1000) + 1;

            //Se ja tinhamos um numero de iteracoes associado ao domain, usar esse
            if (itersByDomain.containsKey(dom)) {
                iter = itersByDomain.get(dom);
            }
            else 
            {
                itersByDomain.put(dom, iter);
            }

            if (firstAdd) {
                //Registar novo salt num file exclusivo do cliente para persistencia
                File newSaltFile = new File("salt_" + userId + "_" + dom + ".txt");
                newSaltFile.createNewFile();

                try (FileOutputStream fos = new FileOutputStream(newSaltFile)) {
                    fos.write(salt);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                //Registar nova iter num file exclusivo do cliente para persistencia
                BufferedWriter wr = new BufferedWriter(new FileWriter("iters_" + userId + ".txt", true));
                wr.write(dom + ":" + iter + System.getProperty("line.separator"));
                wr.close();
            }

            //Gerar a domain key
            SecretKey domainKey = UtilsClient.generateDomainKey(password, salt, iter);

            //Get da public key do user que queremos adicionar pelo certificado na trustore
            Certificate cert = tstore.getCertificate(userId.split("@")[0]);
            PublicKey destUserPubKey = cert.getPublicKey();

            //Wrap da domain key com a public key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, destUserPubKey);
            byte[] dkSend = cipher.wrap(domainKey);

            //Enviar a key cifrada para o server
            out.writeObject(dkSend);
            out.flush();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
    
}
