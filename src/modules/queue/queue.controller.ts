import { Controller, Get, Post, Delete, Param } from '@nestjs/common';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { QueueService } from './queue.service';

@Controller('queue')
export class QueueController {
  constructor(private readonly queueService: QueueService) {}

  @Get('health')
  @Permissions('system:queue')
  async getHealth(): Promise<{
    isHealthy: boolean;
    queues: {
      name: string;
      status: 'active' | 'paused';
      stats: any;
    }[];
  }> {
    return this.queueService.getQueueHealth();
  }

  @Get('email/stats')
  @Permissions('system:queue')
  async getEmailStats(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
  }> {
    return this.queueService.getEmailQueueStats();
  }

  @Get('email/failed')
  @Permissions('system:queue')
  async getFailedJobs(): Promise<any[]> {
    return this.queueService.getFailedJobs();
  }

  @Post('email/pause')
  @Permissions('system:queue')
  async pauseEmailQueue(): Promise<{ message: string }> {
    await this.queueService.pauseEmailQueue();
    return { message: 'Email queue paused' };
  }

  @Post('email/resume')
  @Permissions('system:queue')
  async resumeEmailQueue(): Promise<{ message: string }> {
    await this.queueService.resumeEmailQueue();
    return { message: 'Email queue resumed' };
  }

  @Post('email/clean')
  @Permissions('system:queue')
  async cleanEmailQueue(): Promise<{ message: string }> {
    await this.queueService.cleanEmailQueue();
    return { message: 'Email queue cleaned' };
  }

  @Post('email/retry-failed')
  @Permissions('system:queue')
  async retryFailedJobs(): Promise<{ message: string }> {
    await this.queueService.retryFailedJobs();
    return { message: 'Failed jobs requeued for retry' };
  }

  @Delete('job/:jobId')
  @Permissions('system:queue')
  async removeJob(@Param('jobId') jobId: string): Promise<{ message: string }> {
    await this.queueService.removeJob(jobId);
    return { message: 'Job removed' };
  }
}
