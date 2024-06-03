#include "TaskQueue.h"

TaskQueue::TaskQueue() : stopWorker(false), workerThread(&TaskQueue::Worker, this) {}

TaskQueue::~TaskQueue() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        stopWorker = true;
    }
    queueCondition.notify_all();
    workerThread.join();
}

void TaskQueue::EnqueueTask(Task task) {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        taskQueue.push(task);
    }
    queueCondition.notify_one();
}

void TaskQueue::Worker() {
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCondition.wait(lock, [this] { return !taskQueue.empty() || stopWorker; });

            if (stopWorker && taskQueue.empty()) {
                return;
            }

            task = std::move(taskQueue.front());
            taskQueue.pop();
        }
        task();
    }
}
