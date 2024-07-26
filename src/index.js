"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encode_jwt = encode_jwt;
exports.decode_jwt = decode_jwt;
exports.validate_jwt = validate_jwt;
const crypto = __importStar(require("crypto"));
function base64UrlEncode(input) {
    return input.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function base64UrlDecode(input) {
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    const pad = input.length % 4;
    if (pad) {
        if (pad === 1)
            throw new Error('Invalid base64 string');
        input += new Array(5 - pad).join('=');
    }
    return Buffer.from(input, 'base64');
}
function encode_jwt(secret, id, payload, ttl) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const extendedPayload = Object.assign(Object.assign({}, payload), { id, iat: now });
    if (ttl) {
        extendedPayload.exp = now + ttl;
    }
    const headerBase64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
    const payloadBase64 = base64UrlEncode(Buffer.from(JSON.stringify(extendedPayload)));
    const signature = crypto.createHmac('sha256', secret).update(`${headerBase64}.${payloadBase64}`).digest('base64');
    const signatureBase64 = base64UrlEncode(Buffer.from(signature, 'base64'));
    return `${headerBase64}.${payloadBase64}.${signatureBase64}`;
}
function decode_jwt(secret, token) {
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
function validate_jwt(secret, token) {
    try {
        decode_jwt(secret, token);
        return true;
    }
    catch (e) {
        return false;
    }
}
