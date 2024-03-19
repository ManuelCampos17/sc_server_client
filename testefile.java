import java.io.*;

public class testefile {
    public static void main(String[] args) {
        String sourceFileName = "donkey.jpg";
        String destinationFileName = "manel_5.jpg";

        try {
            // Read bytes from the source file
            FileInputStream fileInputStream = new FileInputStream(sourceFileName);
            byte[] buffer = new byte[fileInputStream.available()];
            fileInputStream.read(buffer);
            fileInputStream.close();

            // Write bytes to the destination file
            FileOutputStream fileOutputStream = new FileOutputStream(destinationFileName);
            fileOutputStream.write(buffer);
            fileOutputStream.close();

            System.out.println("File conversion successful.");
        } catch (IOException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}