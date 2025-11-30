
export function secureWipe(buffer: Buffer): void {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    return;
  }

  buffer.fill(0);

  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = Math.floor(Math.random() * 256);
  }
  buffer.fill(0);
}

export function secureWipeMultiple(buffers: Buffer[]): void {
  for (const buffer of buffers) {
    secureWipe(buffer);
  }
}

export function stringToSecureBuffer(str: string): Buffer {
  return Buffer.from(str, 'utf8');
}

export function bufferToStringAndWipe(buffer: Buffer): string {
  const str = buffer.toString('utf8');
  secureWipe(buffer);
  return str;
}

export class SecureBuffer {
  private buffer: Buffer;
  private isWiped: boolean = false;

  constructor(data: Buffer | string) {
    if (typeof data === 'string') {
      this.buffer = Buffer.from(data, 'utf8');
    } else {
      this.buffer = Buffer.alloc(data.length);
      data.copy(this.buffer);
    }
  }

  public getBuffer(): Buffer {
    if (this.isWiped) {
      throw new Error('SecureBuffer has been wiped and can no longer be accessed');
    }
    return this.buffer;
  }

  public get length(): number {
    return this.buffer.length;
  }

  public get wiped(): boolean {
    return this.isWiped;
  }

  public wipe(): void {
    if (!this.isWiped) {
      secureWipe(this.buffer);
      this.isWiped = true;
    }
  }

  public toStringAndWipe(): string {
    if (this.isWiped) {
      throw new Error('SecureBuffer has been wiped and can no longer be accessed');
    }
    const str = this.buffer.toString('utf8');
    this.wipe();
    return str;
  }
}

export async function withSecureBuffer<T>(
  data: Buffer | string,
  fn: (buffer: Buffer) => T | Promise<T>
): Promise<T> {
  const secureBuffer = new SecureBuffer(data);
  try {
    return await fn(secureBuffer.getBuffer());
  } finally {
    secureBuffer.wipe();
  }
}

export function secureCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

