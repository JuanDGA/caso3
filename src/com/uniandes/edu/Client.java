package com.uniandes.edu;

import java.io.*;
import java.net.Inet4Address;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {
  private static final String serverPublicKeyPath = "data/key.pub";
  private PublicKey serverKey;

  public Client() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    byte[] publicKeyBytes = Files.readAllBytes(Paths.get(serverPublicKeyPath));
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    this.serverKey = keyFactory.generatePublic(publicKeySpec);
  }

  public void askServer(String id, int packetId) {
    try (
        Socket socket = new Socket(Inet4Address.getLocalHost().getHostAddress(), 8000);
        OutputStream outputStream = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true);
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    ) {
      writer.println("message");
      System.out.println(reader.readLine());
    } catch (Exception e) {
      e.printStackTrace(System.err);
    }
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    System.out.println("Cargando llave publica del servidor...");
    Client client = new Client();

    Scanner scanner = new Scanner(System.in);
    System.out.println("Por favor ingrese el id de usuario:");
    String userId = scanner.next();
    System.out.println("Por favor ingrese el id de paquete a consultar:");
    int packetId = scanner.nextInt();
    client.askServer(userId, packetId);
  }
}
