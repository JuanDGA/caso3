package com.uniandes.edu;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client {
  private static final String serverPublicKeyPath = "data/key.pub";
  private PublicKey serverKey;

  public Client() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    byte[] publicKeyBytes = Files.readAllBytes(Paths.get(serverPublicKeyPath));
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    this.serverKey = keyFactory.generatePublic(publicKeySpec);
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    System.out.println("Cargando llave publica del servidor...");
    Client client = new Client();
  }
}
