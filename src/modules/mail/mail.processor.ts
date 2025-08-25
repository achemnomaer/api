import { Processor, Process } from '@nestjs/bull';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job } from 'bull';
import * as nodemailer from 'nodemailer';
import * as Handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';
import { EmailJob } from './mail.service';

type CompiledTemplate = Handlebars.TemplateDelegate;

@Processor('email')
@Injectable()
export class MailProcessor {
  private readonly logger = new Logger(MailProcessor.name);
  private transporter!: nodemailer.Transporter; // definite assignment
  private templates: Map<string, CompiledTemplate> = new Map();

  constructor(private configService: ConfigService) {
    this.initializeTransporter();
    this.loadTemplates();
  }

  private initializeTransporter(): void {
    const host = this.configService.get<string>('SMTP_HOST');
    const port = this.configService.get<number>('SMTP_PORT', 587);
    const user = this.configService.get<string>('SMTP_USER');
    const pass = this.configService.get<string>('SMTP_PASS');

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465, // true for 465, false for other ports
      auth: user && pass ? { user, pass } : undefined,
      tls: { rejectUnauthorized: false },
    });

    // Optional: verify transporter on boot
    this.transporter.verify().then(
      () => this.logger.log('SMTP transporter verified.'),
      (err) => this.logger.warn(`SMTP transporter verification failed: ${String(err)}`),
    );
  }

  private loadTemplates(): void {
    const templatesDir = path.join(__dirname, '../../..', 'templates');

    if (!fs.existsSync(templatesDir)) {
      this.logger.warn(`Templates directory not found: ${templatesDir}`);
      return;
    }

    const templateFiles = fs
      .readdirSync(templatesDir)
      .filter((file) => file.endsWith('.hbs') || file.endsWith('.handlebars'));

    for (const file of templateFiles) {
      const templateName = path.parse(file).name;
      const templatePath = path.join(templatesDir, file);
      const templateContent = fs.readFileSync(templatePath, 'utf-8');
      const template = Handlebars.compile(templateContent);

      this.templates.set(templateName, template);
      this.logger.log(`Loaded email template: ${templateName}`);
    }
  }

  @Process('send-email')
  async sendEmail(job: Job<EmailJob>): Promise<void> {
    const { to, subject, template, context } = job.data;

    try {
      const templateFn = this.templates.get(template);

      const html = templateFn
        ? templateFn(context)
        : this.createFallbackTemplate(subject, context, template);

      const mailOptions: nodemailer.SendMailOptions = {
        from: this.configService.get<string>('SMTP_FROM'),
        to,
        subject,
        html,
      };

      const result = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email sent successfully to ${to}: ${result.messageId}`);
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(`Failed to send email to ${to}: ${err.message}`, err.stack);
      throw error;
    }
  }

  private createFallbackTemplate(
    subject: string,
    context: Record<string, any>,
    missingTemplateName?: string,
  ): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>${subject}</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #f8f9fa; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; }
            .button { display: inline-block; padding: 10px 20px; background: #007bff; color: #fff; text-decoration: none; border-radius: 5px; }
            .muted { color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Education Consultancy</h1>
            </div>
            <div class="content">
              <h2>${subject}</h2>
              ${missingTemplateName ? `<p class="muted">Template "<strong>${missingTemplateName}</strong>" not found. Using fallback layout.</p>` : ''}
              <p>Hello ${context.firstName || 'User'},</p>
              ${context.otp ? `<p>Your verification code is: <strong>${context.otp}</strong></p>` : ''}
              ${context.frontendUrl ? `<p><a href="${context.frontendUrl}" class="button">Visit Our Platform</a></p>` : ''}
              <p>Best regards,<br/>The Education Consultancy Team</p>
            </div>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} Education Consultancy. All rights reserved.</p>
            </div>
          </div>
        </body>
      </html>
    `;
  }
}
