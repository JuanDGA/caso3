package com.uniandes.edu;

public class Packet {
  private final String id;
  private Status status;

  public Packet(String id, Status status) {
    this.id = id;
    this.status = status;
  }

  public String getId() {
    return id;
  }

  public Status getStatus() {
    return Status.valueOf("");
  }
}
