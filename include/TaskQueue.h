// TaskQueue.h
#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <functional>

class TaskQueue {
public:
    using Task = std::function<void()>;

    TaskQueue();
    ~TaskQueue();

    void EnqueueTask(Task task);

private:
    void Worker();

    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::queue<Task> taskQueue;
    bool stopWorker;
    std::thread workerThread;
};

#endif // TASK_QUEUE_H