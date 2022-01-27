/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TCP_ENDPOINT_H_
#define _TCP_ENDPOINT_H_

#include <functional>
#include <iostream>
#include <mutex>
#include <string>

#include <uvw/tcp.hpp>

#include "baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver::endpoints
{

class TCPEndpoint : public BaseEndpoint
{
private:
    int m_port;
    std::string m_ip;
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::TCPHandle> m_handle;

public:
    explicit TCPEndpoint(const std::string & config);
    ~TCPEndpoint();

    void run(void);
    void close(void);
};
} // namespace engineserver::endpoints

#endif // _TCP_ENDPOINT_H_
