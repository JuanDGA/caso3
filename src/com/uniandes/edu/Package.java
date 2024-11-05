package com.uniandes.edu;

public class Package {
  private final String userId;
  private Status status;

  public Package(String id, Status status) {
    this.userId = id;
    this.status = status;
  }

  public String getUserId() {
    return userId;
  }

  public Status getStatus() {
    return this.status;
  }
}
