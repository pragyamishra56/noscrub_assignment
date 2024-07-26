import * as crypto from 'crypto';

function base64UrlEncode(input: Buffer): string {
  return input.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(input: string): Buffer {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = input.length % 4;
  if (pad) {
    if (pad === 1) throw new Error('Invalid base64 string');
    input += new Array(5 - pad).join('=');
  }
  return Buffer.from(input, 'base64');
}

interface JWTPayload {
  id: string | number;
  exp?: number;
  [key: string]: any;
}

export function encode_jwt(secret: string, id: string | number, payload: object, ttl?: number): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const extendedPayload: JWTPayload = { ...payload, id, iat: now };
  if (ttl) {
    extendedPayload.exp = now + ttl;
  }
  const headerBase64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const payloadBase64 = base64UrlEncode(Buffer.from(JSON.stringify(extendedPayload)));
  const signature = crypto.createHmac('sha256', secret).update(`${headerBase64}.${payloadBase64}`).digest('base64');
  const signatureBase64 = base64UrlEncode(Buffer.from(signature, 'base64'));
  return `${headerBase64}.${payloadBase64}.${signatureBase64}`;
}

export function decode_jwt(secret: string, token: string): { id: string, payload: object, expires_at: Date } {
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  if (!headerB64 || !payloadB64 || !signatureB64) {
    throw new Error('Invalid JWT');
  }

  const header = JSON.parse(base64UrlDecode(headerB64).toString());
  const payload = JSON.parse(base64UrlDecode(payloadB64).toString());
  const signature = base64UrlDecode(signatureB64);

  const expectedSignature = crypto.createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest();
  if (!crypto.timingSafeEqual(signature, expectedSignature)) {
    throw new Error('Invalid signature');
  }

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }

  return { id: payload.id, payload, expires_at: new Date(payload.exp * 1000) };
}

export function validate_jwt(secret: string, token: string): boolean {
  try {
    decode_jwt(secret, token);
    return true;
  } catch (e) {
    return false;
  }
}
