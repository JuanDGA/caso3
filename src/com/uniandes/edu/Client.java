package com.uniandes.edu;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Inet4Address;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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

  private String generateChallenge() {
    byte[] challengeBytes = new byte[32];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(challengeBytes);

    return Base64.getEncoder().encodeToString(challengeBytes);
  }

  private String encryptWithPublicKey(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, serverKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
  }

  public void askServer(String id, int packetId) {
    try (
        Socket socket = new Socket(Inet4Address.getLocalHost().getHostAddress(), 8000);
        OutputStream outputStream = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true);
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    ) {
      writer.println("SECINIT"); // We ask for initialization

      String challenge = generateChallenge();
      String encrypted = encryptWithPublicKey(challenge);

      writer.println(encrypted);

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
