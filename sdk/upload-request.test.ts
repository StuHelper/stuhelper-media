import type { components } from './media.gen';

const request = {
  purpose: 'documents',
  filename: 'lecture.txt',
  content_type: 'text/plain',
  size: 1,
  sha256: '0000000000000000000000000000000000000000000000000000000000000000',
} satisfies components['schemas']['UploadRequest'];
void request;
