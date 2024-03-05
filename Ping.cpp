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

#include "Ping.h"

Ping::Ping(std::string name)
{
    m_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    m_name = name;
    m_active = true;
    m_ttl = DEFAULT_TTL;
    m_max_replies = -1;
    m_packets_received = 0;
    m_packets_transmitted = 0;
    m_identifier = static_cast<uint16_t>(rand() % UINT16_MAX);

    /* atributes based on sliding window*/
    m_window = SlidingWindow();
    m_window_store_interval = SlidingWindow();

    has_error = false;
    has_sent_packet = false;
    has_recv_packet = false;
    has_correct_hostName = true;

    gettimeofday(&m_total_time, NULL);

    // Setting options for sockets, error socket and ttl
    if (m_sock == -1)
    {
        std::cout << "! ERROR     | " << m_name << ": Error creating socket " << strerror(errno) << std::endl;
        setActive();
    }
    int optval = 1;
    if (setsockopt(m_sock, SOL_IP, IP_RECVERR, &optval, sizeof(optval)) == -1)
    {
        std::cout << "! ERROR     | " << m_name << ": Error setting IP_RECVERR option " << strerror(errno) << std::endl;
    }

    socklen_t ttl = m_ttl;
    if (setsockopt(m_sock, 0, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        std::cout << "! ERROR     | " << m_name << ": ttl " << strerror(errno) << std::endl;
    }
    m_ttl = ttl;
}

void Ping::setDestination(std::string string_addr)
{
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin_family = AF_INET;
    inet_pton(AF_INET, string_addr.c_str(), &(m_addr.sin_addr));
}

void Ping::setIcmpHdr()
{
    m_icmp_hdr.icmp_type = ICMP_ECHO;
    m_icmp_hdr.icmp_code = 0;
    m_icmp_hdr.icmp_id = htons(getpid());
    m_icmp_hdr.icmp_seq = 1;
    m_icmp_hdr.icmp_cksum = 0;
    m_icmp_hdr.icmp_hun.ih_idseq.icd_id = htons(m_identifier);

    // Calculate the payload size (subtract 8 bytes for the ICMP header)
    size_t payload_size = m_packet_size - 8;

    // Create a payload vector of the desired size
    std::vector<uint8_t> payload(payload_size, 0);

    // Create an ICMP packet buffer with the correct size
    std::vector<uint8_t> icmp_packet(sizeof(m_icmp_hdr) + payload_size);

    // Copy the header and payload into the ICMP packet buffer
    memcpy(icmp_packet.data(), &m_icmp_hdr, sizeof(m_icmp_hdr));
    memcpy(icmp_packet.data() + sizeof(m_icmp_hdr), payload.data(), payload_size);

    m_icmp_hdr.icmp_cksum = checksum(icmp_packet.data(), icmp_packet.size());
    memcpy(icmp_packet.data(), &m_icmp_hdr, sizeof(m_icmp_hdr));
}

unsigned short Ping::checksum(void *data, int len)
{
    unsigned short *buf = (unsigned short *)data;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
    {
        sum += *buf++;
    }
    if (len == 1)
    {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void Ping::increaseHdr()
{
    m_icmp_hdr.icmp_seq++;
    m_icmp_hdr.icmp_cksum = 0;
    m_icmp_hdr.icmp_cksum = checksum(&m_icmp_hdr, sizeof(m_icmp_hdr));
}

int Ping::sendPacket()
{
    struct timeval s_time;
    gettimeofday(&s_time, NULL);
    m_start_time = s_time;

    // function that sends data
    int res_send = sendto(m_sock, &m_icmp_hdr, sizeof(m_icmp_hdr), 0, (sockaddr *)&m_addr, sizeof(m_addr));

    if (res_send <= 0)
    {
        std::cout << "! ERROR     | " << m_name << ": Error sending ICMP packet to " << inet_ntoa(m_addr.sin_addr) << ": " << strerror(errno) << std::endl;
    }
    else
    {
        std::cout << std::left << "| SEND      |"
                  << std::setw(8) << "name: " << std::setw(20) << m_name
                  << std::setw(10) << "to destination: " << std::setw(20) << inet_ntoa(m_addr.sin_addr)
                  << std::setw(10) << "header size: " << std::setw(12) << sizeof(m_icmp_hdr)
                  << std::setw(10) << "packet size: " << std::setw(12) << m_packet_size
                  << std::setw(10) << "sent packets: " << std::setw(12) << res_send << std::endl
                  << std::endl;
    }

    if (has_sent_packet == false)
    {
        last_sent_timestamp = std::chrono::steady_clock::now();
    }

    has_sent_packet = true;
    m_packets_transmitted++;
    return res_send;
}

void Ping::receivePacket(sysrepo::Session oper_session, int bytes_received)
{
    double elapsed_time = elapsedTime();
    oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/result/reply[icmp-sequence='" + std::to_string(getIcmpSequence()) + "']/destination-ip-address", getDestination());
    updateRecvStatistics(oper_session, elapsed_time);
    setMaxReplies();

    std::cout << std::left << "| RECEIVE   |"
              << std::setw(8) << "name: " << std::setw(20) << getName()
              << std::setw(11) << "from addr: " << std::setw(25) << getDestination()
              << std::setw(10) << "icmp_seq: " << std::setw(15) << getIcmpSequence()
              << std::setw(10) << "RTT (ms): " << std::setw(15) << elapsed_time
              << std::setw(10) << "received bytes: " << std::setw(8) << bytes_received
              << std::setw(5) << "TTL: " << getTtl() << std::endl
              << std::endl;

   increaseHdr();
}

void Ping::updateRecvStatistics(sysrepo::Session oper_session, double elapsed_time)
{
    if (elapsed_time != -1)
    {
        m_window.addElapsedTime(elapsed_time);

        oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/result/reply[icmp-sequence='" + std::to_string(getIcmpSequence()) + "']/response-time", std::to_string(elapsed_time));
        oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/result/reply[icmp-sequence='" + std::to_string(getIcmpSequence()) + "']/time-to-live", std::to_string(getTtl()));

        double avg = m_window.getAverageResponseTime();
        double best = m_window.getBestResponseTime();
        double worst = m_window.getWorstResponseTime();
        double jitter = m_window.calculateJitter(m_window.calculateAverageInterArrivalTime(m_window.getElapsedTimes()));

        double avg_rounded = std::round(avg * 1000) / 1000.0;
        double best_rounded = std::round(best * 1000) / 1000.0;
        double worst_rounded = std::round(worst * 1000) / 1000.0;
        double jitter_rounded = std::round(jitter * 1000) / 1000.0;

        oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/average-response-time", std::to_string(avg_rounded));
        oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/best-response-time", std::to_string(best_rounded));
        oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/worst-response-time", std::to_string(worst_rounded));
        oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/jitter", std::to_string(jitter_rounded));
        oper_session.applyChanges();
        m_window_store_interval.removeOldRecordsFromSysrepo(oper_session, "/probe:commands/ping[name='" + m_name + "']/result/reply[icmp-sequence='" + std::to_string(getIcmpSequence()) + "']");
    }

    int total_rounded = countTotalTime();
    int transmitted = getPacketsTransmitted();
    int received = getPacketsReceived();

    if (elapsed_time != -1)
    {
        m_packets_received++;
        received = m_packets_received;
    }

    int packet_loss_integer = 0;

    if (transmitted != 0)
    {
        int packet_loss_percent = ((transmitted - received) * 100) / transmitted;
        packet_loss_integer = static_cast<int>(packet_loss_percent);
    }

    oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/packets-received", std::to_string(received));
    oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/packet-loss", std::to_string(packet_loss_integer));
    oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/packets-transmitted", std::to_string(transmitted));
    oper_session.setItem("/probe:commands/ping[name='" + m_name + "']/statistics/total-time", std::to_string(total_rounded));
    oper_session.applyChanges();
}

double Ping::countTotalTime()
{
    struct timeval end_time;
    gettimeofday(&end_time, NULL);

    double total = (double)(end_time.tv_sec - m_total_time.tv_sec) + (double)(end_time.tv_usec - m_total_time.tv_usec) / 1000000;
    double total_rounded = std::round(total * 1000) / 1000.0;
    return total_rounded;
}

bool Ping::correctHostname()
{
    return has_correct_hostName;
}

bool Ping::hasError(int error)
{
    if (error == 1)
    {
        has_error = true;
    }
    else if (error == 0)
    {
        has_error = false;
    }
    return has_error;
}

double Ping::elapsedTime() // counting of response time
{
    struct timeval m_end_time;
    gettimeofday(&m_end_time, NULL);

    double response_time = (m_end_time.tv_sec - m_start_time.tv_sec) * 1000;
    response_time += (m_end_time.tv_usec - m_start_time.tv_usec) / 1000.0;

    return response_time;
}

int Ping::setTimer(int timers)
{
    int m_rfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (m_rfd == -1)
    {
        std::cout << "! ERROR     | " << m_name << ": Error creating timerfd" << strerror(errno) << std::endl;
    }

    // Set initial expiration and interval for both timers (in milliseconds)
    struct itimerspec timer;
    memset(&timer, 0, sizeof(timer));

    timer.it_interval.tv_sec = timers;       // time between packets
    timer.it_value.tv_sec = STARTER_TIMEOUT; // time to wait at the beginning

    if (timerfd_settime(m_rfd, 0, &timer, nullptr) == -1)
    {
        std::cout << "! ERROR     | " << m_name << ": Error setting timerfd time" << strerror(errno) << std::endl;
    }

    return m_rfd;
}

void Ping::setSwitch(std::vector<std::string> switches)
{
    int counter = 0; // keep track of current value being assigned

    for (auto &value : switches)
    {
        switch (counter)
        {

        // destination-ip-address
        case 0:

            if (value != "")
            {
                setDestination(value);
            }
            break;

        // destination-domain-name
        case 1:

            if (value != "")
            {
                const char *hostname = value.c_str();
                struct hostent *host;
                if ((host = gethostbyname(hostname)) == NULL)
                {
                    std::cout << "! ERROR     | " << m_name << ": failed to resolve hostname" << std::endl;
                    has_correct_hostName = false;
                }
                else
                {
                    struct in_addr **addr_list = (struct in_addr **)host->h_addr_list;
                    std::string destination = inet_ntoa(*addr_list[0]);
                    setDestination(destination);
                }
            }

            break;

        // max-replies
        case 2:

            if (value != "")
            {
                std::string str = value;
                m_max_replies = std::stoi(str);
                break;
            }
            else
            {
                m_max_replies = -1;
                break;
            }
        // source-address
        case 3:
            if (value != "")
            {
                struct sockaddr_in src_addr;
                memset(&src_addr, 0, sizeof(src_addr));
                src_addr.sin_family = AF_INET;
                src_addr.sin_addr.s_addr = inet_addr(value.c_str());
                bind(m_sock, (struct sockaddr *)&src_addr, sizeof(src_addr));
            }
            break;
        // interface-name
        case 4:

            if (value != "")
            {
                const char *ifname = value.c_str();
                setsockopt(m_sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1);
            }
            break;
        // time-between-packets
        case 5:
            if (value != "")
            {
                m_time_between_packets = std::stoi(value);
                m_rfd = setTimer(m_time_between_packets);
            }
            else
            {
                m_time_between_packets = DEFAULT_TIME;
                m_rfd = setTimer(m_time_between_packets);
            }

            break;

        // packet-size
        case 6:
            m_packet_size = DEFAULT_SIZE;
            if (value != "")
            {
                m_packet_size = std::stoi(value);
            }

            setIcmpHdr();
            break;

        // reply-timeout
        case 7:

            if (value != "")
            {
                m_reply_timeout = std::stoi(value);
                break;
            }else{
                m_reply_timeout = m_time_between_packets * 3000;    // if reply timeout is not set, the value it will wait is 3x time_between_packets
                break;
            }

        // store-interval
        case 8:
            if (value != "")
            {
                int store_interval = std::stoi(value);
                m_window_store_interval.setWindowSize(store_interval);
                break;
            }
            else
            {
                m_window_store_interval.setWindowSize(DEFAULT_STORE_INTERVAL);
            }

        // statistics-interval
        case 9:
            if (value != "")
            {
                double m_statistics_interval = std::stoi(value);
                m_window.setWindowSize(m_statistics_interval);
                break;
            }
            else
            {
                m_window.setWindowSize(DEFAULT_STATISTICS_INTERVAL);
            }
        default:
            break;
        }
        counter++;
    }
}

void Ping::setMaxReplies()
{
    m_max_replies--;
}

bool Ping::setReceivedPacket(bool recv_status)
{
    has_recv_packet = recv_status;
    return has_recv_packet;
}

bool Ping::isActive()
{
    return m_active;
}

void Ping::setActive()
{
    m_active = false;
}

bool Ping::isTimedOut()
{
    if (!has_recv_packet)
    {
        if (has_sent_packet)
        {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_sent_timestamp).count();
            if (elapsed_ms > m_reply_timeout)
            {
                return true;
            }
        }
    }
    return false;
}

uint16_t Ping::getIdentifier()
{
    return m_identifier;
}
std::string Ping::getName()
{
    return m_name;
}

icmp Ping::getHdr()
{

    return m_icmp_hdr;
}

int Ping::getTtl()
{
    return m_ttl;
}

int Ping::getIcmpSequence()
{
    return m_icmp_hdr.icmp_seq;
}

int Ping::getSocket()
{
    return m_sock;
}

int Ping::getPacketsReceived()
{
    return m_packets_received;
}

int Ping::getPacketsTransmitted()
{
    return m_packets_transmitted;
}

int Ping::getRfd()
{
    return m_rfd;
}

char *Ping::getDestination()
{
    char *ip = inet_ntoa(m_addr.sin_addr);
    return ip;
}

sockaddr_in Ping::getAddr()
{
    return m_addr;
}

int Ping::getMaxReplies()
{
    return m_max_replies;
}

int Ping::getPacketSize()
{
    return m_packet_size;
}
