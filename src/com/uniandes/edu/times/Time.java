package com.uniandes.edu.times;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

public class Time {
  private final LocalDateTime startTime = LocalDateTime.now();
  private LocalDateTime endTime;
  public String name = "";

  public Time() { }

  public Time(String name) {
    this.name = name + "=";
  }

  public void close() {
    this.endTime = LocalDateTime.now();
  }

  public long nanoseconds() {
    return ChronoUnit.NANOS.between(startTime, endTime);
  }

  @Override
  public String toString() {
    return name + nanoseconds() + "ns";
  }
}
