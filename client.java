import java.io.*;
import java.net.Socket;

public class client {
    private static Socket socket;
    public static void main(String[] args) {
        try {
            String sourceFileName = "donkey.jpg";
            String serverAddress = "127.0.0.1"; // Server IP address
            int serverPort = 12345; // Server port
            socket = new Socket(serverAddress, serverPort);

            ei(sourceFileName);
        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    public static void ei(String sourceFileName){

        try (
             FileInputStream fileInputStream = new FileInputStream(sourceFileName);
             OutputStream outputStream = socket.getOutputStream()) {

            // Read the entire file into memory
            byte[] fileData = fileInputStream.readAllBytes();
            int fileSize = fileData.length;

            // Write the file size to the output stream
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            dataOutputStream.writeInt(fileSize);

            // Write the file data to the output stream
            outputStream.write(fileData);
            outputStream.flush(); // Ensure all data is sent
            
            System.out.println("File sent to server successfully.");
            
        } catch (IOException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
