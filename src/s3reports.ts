import crypto from 'crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

export interface S3ReportConfig {
  bucketName: string;
  region: string;
  accessKey: string;
  secretAccessKey: string;
  folderPath: string;
}

export function getS3ReportConfig(): S3ReportConfig | null {
  const bucketName = process.env.BUCKET_NAME;
  const region = process.env.BUCKET_REGION;
  const accessKey = process.env.ACCESS_KEY;
  const secretAccessKey = process.env.SECRET_ACCESS_KEY;
  const folderPath = (process.env.FOLDER_PATH ?? 'report/').replace(/\/?$/, '/');

  if (!bucketName || !region || !accessKey || !secretAccessKey) {
    return null;
  }
  return { bucketName, region, accessKey, secretAccessKey, folderPath };
}

export function isS3UploadEnabled(): boolean {
  return getS3ReportConfig() !== null;
}

/**
 * Generate a random report filename (e.g. report/security-report-a1b2c3d4-1708123456789.json).
 */
export function randomReportFileName(folderPath: string, ext: string = 'json'): string {
  const suffix = crypto.randomBytes(8).toString('hex');
  const timestamp = Date.now();
  return `${folderPath}security-report-${suffix}-${timestamp}.${ext}`;
}

/**
 * S3 key for a given scan: report/security-report-{scanId}.json
 */
export function reportKeyForScanId(folderPath: string, scanId: string, ext: string = 'json'): string {
  const safe = String(scanId).replace(/[^a-zA-Z0-9_-]/g, '_');
  return `${folderPath}security-report-${safe}.${ext}`;
}

export type S3ReportFormat = 'json' | 'html';

/**
 * Upload report content to S3.
 * If scanId is provided, key is report/security-report-{scanId}.{ext}; otherwise a random name is used.
 * Returns the S3 key (path) of the uploaded file, or throws on failure.
 */
export async function uploadReportToS3(
  content: string,
  scanId?: string,
  format: S3ReportFormat = 'json'
): Promise<string> {
  const config = getS3ReportConfig();
  if (!config) {
    throw new Error('S3 upload is not configured. Set BUCKET_NAME, BUCKET_REGION, ACCESS_KEY, SECRET_ACCESS_KEY (and optionally FOLDER_PATH) in .env');
  }

  const ext = format;
  const contentType = format === 'html' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8';
  const key = scanId
    ? reportKeyForScanId(config.folderPath, scanId, ext)
    : randomReportFileName(config.folderPath, ext);
  const client = new S3Client({
    region: config.region,
    credentials: {
      accessKeyId: config.accessKey,
      secretAccessKey: config.secretAccessKey
    }
  });

  const command = new PutObjectCommand({
    Bucket: config.bucketName,
    Key: key,
    Body: content,
    ContentType: contentType
  });

  await client.send(command);
  return key;
}