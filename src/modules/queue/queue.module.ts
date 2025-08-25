import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { QueueService } from './queue.service';
import { QueueController } from './queue.controller';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'email',
    }),
  ],
  controllers: [QueueController],
  providers: [QueueService],
  exports: [QueueService],
})
export class QueueModule {}