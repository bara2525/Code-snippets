/*
 * Copyright (c) 2023 Barbora Rutarova
 * All rights reserved.
 *
 * This code is protected by copyright law. If you want to use, modify, or distribute
 * this code, you must obtain prior written permission from the author.
 *
 * The code is provided as is, without any warranties or conditions.
 * The author shall not be liable for any damages arising from the use or inability
 * to use this code, including, but not limited to, direct, indirect, incidental,
 * consequential, or other damages.
 *
 */

#ifndef PING
#define PING

#include "SlidingWindow.h"

/* standard libraries*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <iomanip>

#include <errno.h>
#include <malloc.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bits/stdc++.h>

#include <sys/time.h>
#include <sys/timerfd.h>

/* network related libraries*/
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

/* sysrepo and libyang libraries*/
#include <sysrepo-cpp/Session.hpp>
#include <libyang-cpp/Value.hpp>

#define MAX_PAYLOAD_SIZE 1024
#define DEFAULT_TIME 5
#define DEFAULT_SIZE 64
#define DEFAULT_TTL 64
#define DEFAULT_STATISTICS_INTERVAL -1
#define DEFAULT_STORE_INTERVAL -1
#define STARTER_TIMEOUT 1


class Ping
{
private:
  /* variables for ping construction*/
  int m_ttl;
  int m_sock;
  icmp m_icmp_hdr;
  std::string m_name;
  sockaddr_in m_addr;
  uint16_t m_identifier;

  /* variables of switches */
  int m_rfd; // timer socket
  int m_max_replies;
  int m_packet_size;
  int m_reply_timeout;
  int m_time_between_packets;
  SlidingWindow m_window;                // window for statistics interval
  SlidingWindow m_window_store_interval; // window for store interval

  /* verification variable */
  bool m_active;
  bool has_error;
  bool has_sent_packet;
  bool has_recv_packet;
  bool has_correct_hostName;
  bool has_displayed_unreachable;

  /* statistics varibales */
  int m_packets_received;
  int m_packets_transmitted;
  struct timeval m_start_time;
  struct timeval m_total_time;                               // variable used to determine how long has been program running
  std::chrono::steady_clock::time_point last_sent_timestamp; // when was packet last sent
  std::chrono::steady_clock::time_point last_recv_timestamp; // when was packet last received

public:
  Ping(std::string name); // constructor

  /* functions for sending and receiving */
  void setIcmpHdr();
  void setDestination(std::string string_addr);
  int sendPacket();
  void increaseHdr();
  double elapsedTime();  // counts elapsed time
  double countTotalTime();
  unsigned short checksum(void *data, int len);

  void receivePacket(sysrepo::Session oper_session, int bytes_received);
  void updateRecvStatistics(sysrepo::Session oper_session, double elapsed_time);
  void updateErrorStatistics(sysrepo::Session oper_session);

  /* getters */
  icmp getHdr();
  int getRfd();
  int getTtl();
  int getSocket();
  int getMsgCount();
  int getMaxReplies();
  int getPacketSize();
  int getIcmpSequence();
  sockaddr_in getAddr();
  std::string getName();
  char *getDestination();   // returns ip address in char
  uint16_t getIdentifier();
  int getPacketsReceived();
  int getPacketsTransmitted();

  /* setters */
  void setActive();
  bool isTimedOut();
  void setMaxReplies();
  int setTimer(int timer);
  bool setReceivedPacket(bool recv_status);
  void setSwitch(std::vector<std::string> switches);
  
  /*verification function*/
  bool isActive();
  bool correctHostname();
  bool hasError(int error);
};

#endif