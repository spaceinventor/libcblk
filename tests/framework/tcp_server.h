#pragma once

#include <pthread.h>

class TCPServer
{
public:
    TCPServer(unsigned short port);

    int start();
    int stop();

    unsigned short m_port;

private:
    bool m_keep_running;
    pthread_t m_worker_task;

    static void *worker_task_fnc(void *param);
};
