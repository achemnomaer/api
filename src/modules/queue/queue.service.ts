import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue, JobOptions } from 'bull';

@Injectable()
export class QueueService {
  constructor(
    @InjectQueue('email') private emailQueue: Queue,
  ) {}

  // Email queue methods
  async addEmailJob(
    jobName: string, 
    data: any, 
    options?: JobOptions
  ): Promise<any> {
    return this.emailQueue.add(jobName, data, {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000,
      },
      removeOnComplete: 100,
      removeOnFail: 50,
      ...options,
    });
  }

  async getEmailQueueStats(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
  }> {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.emailQueue.getWaiting(),
      this.emailQueue.getActive(),
      this.emailQueue.getCompleted(),
      this.emailQueue.getFailed(),
      this.emailQueue.getDelayed(),
    ]);

    return {
      waiting: waiting.length,
      active: active.length,
      completed: completed.length,
      failed: failed.length,
      delayed: delayed.length,
    };
  }

  async pauseEmailQueue(): Promise<void> {
    await this.emailQueue.pause();
  }

  async resumeEmailQueue(): Promise<void> {
    await this.emailQueue.resume();
  }

  async cleanEmailQueue(grace: number = 5000): Promise<void> {
    await this.emailQueue.clean(grace, 'completed');
    await this.emailQueue.clean(grace, 'failed');
  }

  async retryFailedJobs(): Promise<void> {
    const failedJobs = await this.emailQueue.getFailed();
    
    for (const job of failedJobs) {
      await job.retry();
    }
  }

  async getFailedJobs(): Promise<any[]> {
    const failedJobs = await this.emailQueue.getFailed();
    return failedJobs.map(job => ({
      id: job.id,
      name: job.name,
      data: job.data,
      failedReason: job.failedReason,
      attemptsMade: job.attemptsMade,
      timestamp: job.timestamp,
    }));
  }

  async removeJob(jobId: string): Promise<void> {
    const job = await this.emailQueue.getJob(jobId);
    if (job) {
      await job.remove();
    }
  }

  // General queue utilities
  async getQueueHealth(): Promise<{
    isHealthy: boolean;
    queues: {
      name: string;
      status: 'active' | 'paused';
      stats: any;
    }[];
  }> {
    const emailStats = await this.getEmailQueueStats();
    const emailStatus = await this.emailQueue.isPaused() ? 'paused' : 'active';

    const queues = [
      {
        name: 'email',
        status: emailStatus as 'active' | 'paused',
        stats: emailStats,
      },
    ];

    // Consider queue healthy if not too many failed jobs
    const isHealthy = queues.every(queue => 
      queue.stats.failed < 10 && queue.status === 'active'
    );

    return {
      isHealthy,
      queues,
    };
  }
}