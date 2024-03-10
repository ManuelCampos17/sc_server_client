// <serverAddress> identifica o servidor. O formato de serverAddress é o seguinte:
// <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o
// porto é opcional. Por omissão, o cliente deve ligar-se ao porto 12345 do servidor.
// • <dev-id> - número inteiro que identifica o dispositivo.
// • <user-id> - string que identifica o (endereço de email do) utilizador local.

// IoTDevice <serverAddress> <dev-id> <user-id>

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.util.Scanner;

// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
// NOTA: COMPARAR OS OUT & IN do CLIENTE E DO SERVIDOR para garantir que não há falhas
// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
public class IoTDevice {
    
    public static void main(String[] args) {
        try {
            System.out.println("Client Initializing...");
            Scanner sc = new Scanner(System.in); 

            // Verificar o numero de argumentos
            if(!argsCheck(args)){
                return;
            }

            // Iniciar a ligação ao servidor
            String serverAddress;
            int port = 12345;
            String[] addr = args[0].split(":");
            int devId = Integer.parseInt(args[1]);
            String userId = args[2];

            if(addr.length == 1){
                serverAddress = addr[0];
            } else {
                serverAddress = addr[0];
                port = Integer.parseInt(addr[1]);
            }

            Socket clientSocket = new Socket(serverAddress, port);
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

            //Pedir a password
            System.out.print("Insere a tua Password: ");
            String password = sc.nextLine();

            //Enviar a password
            out.writeObject(userId + ":" + password);

            String msgPass = (String) in.readObject();
            
            //Loop para verificar a password
            while (msgPass.equals("WRONG-PWD")) {
                System.out.println("Password Errada");
                System.out.print("Insere a tua Password: ");
                password = sc.nextLine();
                out.writeObject(userId + ":" + password);
                msgPass = (String) in.readObject();
            }

            System.out.println(msgPass);

            //Enviar o devId
            out.writeObject(devId);

            //Receber resposta
            String msgDevId = (String) in.readObject();
            while (msgDevId.equals("NOK-DEVID")) {
                System.out.println();
                System.out.println("Device ID em Utilização");
                System.out.print("Insere um novo Device ID: ");
                devId = sc.nextInt();
                out.writeObject(devId);
                msgDevId = (String) in.readObject();
            }

            System.out.println(msgDevId);







        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

public static boolean argsCheck(String[] args){
    if (args.length != 3){
        System.out.println("---------------------------------");
        System.out.println("--Incorrect number of arguments--");
        System.out.println("--> IoTDevice <serverAddress> <dev-id> <user-id> <--");
        System.out.println("---------------------------------");
        return false;
    }
    return true;
}
