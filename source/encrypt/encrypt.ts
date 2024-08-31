import * as webdav from "../index";
import type {
    WebDAVClient,
    FileStat,
    WebDAVClientOptions,
    RequestOptions,
    Response,
    GetDirectoryContentsOptions,
    CreateDirectoryOptions,
    PutFileContentsOptions,
    ResponseDataDetailed,
    DiskQuota,
    BufferLike,
    CreateReadStreamOptions,
    CreateWriteStreamCallback,
    CreateWriteStreamOptions,
    DAVCompliance,
    LockOptions,
    LockResponse,
    SearchOptions,
    SearchResult,
    WebDAVMethodOptions,
    GetFileContentsOptions,
    RequestOptionsCustom,
    MoveFileOptions,
    CopyFileOptions,
    StatOptions,
    GetQuotaOptions,
    Headers
} from "../types";

import { getPatcher, parseStat, parseXML, AuthType } from "../index";
import stream, { Readable, Writable } from "stream";
import { isReactNative, isWeb } from "../compat/env";
import { Buffer } from "buffer";
/////////////

class ChaCha20 {
    private state: Uint32Array;

    constructor(key: Uint8Array, nonce: Uint8Array) {
        if (key.length !== 32) throw new Error("ChaCha20 key must be 32 bytes");
        if (nonce.length !== 12) throw new Error("ChaCha20 nonce must be 12 bytes");

        this.state = new Uint32Array(16);

        // Set up the initial state
        this.state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574], 0); // Constants
        this.state.set(this.toUint32Array(key), 4); // Key
        this.state[12] = 0; // Counter
        this.state.set(this.toUint32Array(nonce), 13); // Nonce
    }

    encrypt(plaintext: Uint8Array): Uint8Array {
        return this.process(plaintext);
    }

    decrypt(ciphertext: Uint8Array): Uint8Array {
        return this.process(ciphertext);
    }

    private process(data: Uint8Array): Uint8Array {
        const output = new Uint8Array(data.length);
        let counter = 0;

        for (let i = 0; i < data.length; i += 64) {
            const keyStream = this.generateKeyStream(counter);
            for (let j = 0; j < 64 && i + j < data.length; j++) {
                output[i + j] = data[i + j] ^ keyStream[j];
            }
            counter++;
        }

        return output;
    }

    private generateKeyStream(counter: number): Uint8Array {
        const workingState = new Uint32Array(this.state);
        workingState[12] = counter;

        // 20 rounds (10 column rounds and 10 diagonal rounds)
        for (let i = 0; i < 10; i++) {
            // Column round
            this.quarterRound(workingState, 0, 4, 8, 12);
            this.quarterRound(workingState, 1, 5, 9, 13);
            this.quarterRound(workingState, 2, 6, 10, 14);
            this.quarterRound(workingState, 3, 7, 11, 15);
            // Diagonal round
            this.quarterRound(workingState, 0, 5, 10, 15);
            this.quarterRound(workingState, 1, 6, 11, 12);
            this.quarterRound(workingState, 2, 7, 8, 13);
            this.quarterRound(workingState, 3, 4, 9, 14);
        }

        // Add the original state to the working state
        for (let i = 0; i < 16; i++) {
            workingState[i] += this.state[i];
        }

        return new Uint8Array(workingState.buffer);
    }

    private quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = this.rotl(state[d], 16);
        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = this.rotl(state[b], 12);
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = this.rotl(state[d], 8);
        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = this.rotl(state[b], 7);
    }

    private rotl(v: number, c: number): number {
        return (v << c) | (v >>> (32 - c));
    }

    private toUint32Array(array: Uint8Array): Uint32Array {
        const uint32Array = new Uint32Array(array.length / 4);
        for (let i = 0; i < array.length; i += 4) {
            uint32Array[i / 4] =
                (array[i] | (array[i + 1] << 8) | (array[i + 2] << 16) | (array[i + 3] << 24)) >>>
                0;
        }
        return uint32Array;
    }
}

class StreamCipher {
    private chacha: ChaCha20;

    constructor(password: string) {
        // 使用密码生成32字节的密钥和12字节的nonce
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);
        const key = this.deriveKey(passwordBytes, 32);
        const nonce = this.deriveKey(passwordBytes, 12);
        this.chacha = new ChaCha20(key, nonce);
    }

    encrypt(plaintext: Uint8Array): Uint8Array {
        return this.chacha.encrypt(plaintext);
    }

    decrypt(ciphertext: Uint8Array): Uint8Array {
        return this.chacha.decrypt(ciphertext);
    }

    // 简单的密钥派生函数
    private deriveKey(password: Uint8Array, length: number): Uint8Array {
        const result = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            result[i] = password[i % password.length];
        }
        return result;
    }
}

/////////////

interface EncryptedWebDAVClientOptions extends WebDAVClientOptions {
    secretKey?: string;
    encrypt?: boolean;
    customEncrypt?: {
        encrypt: (plaintext: Uint8Array) => Uint8Array;
        decrypt: (ciphertext: Uint8Array) => Uint8Array;
    };
}

export default class EncryptedWebDAVClient implements WebDAVClient {
    private client: WebDAVClient;
    private globalEncrypt: boolean;
    private secretKey: string;

    constructor(remoteURL: string, options: EncryptedWebDAVClientOptions) {
        const { secretKey: encryptionKey, encrypt, ...clientOptions } = options;
        this.client = webdav.createClient(remoteURL, clientOptions);
        this.globalEncrypt = encrypt || false;
        this.secretKey = options.secretKey;
        if (options.customEncrypt) {
            this.decrypt = options.customEncrypt.decrypt;
            this.encrypt = options.customEncrypt.decrypt;
        } else {
            let c = new StreamCipher(encryptionKey);
            this.decrypt = c.decrypt.bind(c);
            this.encrypt = c.encrypt.bind(c);
        }
    }
    createReadStream(path: string, options?: CreateReadStreamOptions): Readable {
        const shouldEncrypt = this.shouldEncrypt();

        path = shouldEncrypt ? this.encryptPath(path) : path;
        // 定义加密密钥

        let readableStream = this.client.createReadStream(path, options);

        if (shouldEncrypt) {
            let that = this;
            // 创建一个转换流来解密数据
            const encryptStream = new stream.Transform({
                transform(chunk, encoding, callback) {
                    // 使用 crypto-js解密数据
                    const decrypted = that.decrypt(chunk);
                    // 将解密后的数据推送到输出流
                    this.push(decrypted);
                    callback();
                }
            });

            const encryptedStream = readableStream.pipe(encryptStream);
            return encryptedStream;
        } else {
            return readableStream;
        }
    }
    createWriteStream(
        path: string,
        options?: CreateWriteStreamOptions,
        callback?: CreateWriteStreamCallback
    ): Writable {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        // 定义加密密钥

        let writeStream = this.client.createWriteStream(path, options, callback);

        if (shouldEncrypt) {
            let that = this;
            // 创建一个转换流来加密数据
            const encryptStream = new stream.Transform({
                transform(chunk, encoding, callback) {
                    // 使用 crypto-js 加密数据
                    const encrypted = that.encrypt(chunk);
                    // 将加密后的数据推送到输出流
                    this.push(encrypted);
                    callback();
                }
            });

            const encryptedStream = writeStream.pipe(encryptStream);
            return encryptedStream;
        } else {
            return writeStream;
        }
    }
    async getDAVCompliance(path: string): Promise<DAVCompliance> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await this.client.getDAVCompliance(path);
    }
    async lock(path: string, options?: LockOptions): Promise<LockResponse> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await this.client.lock(path, options);
    }

    async search(
        path: string,
        options?: SearchOptions
    ): Promise<SearchResult | ResponseDataDetailed<SearchResult>> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;

        let res = await this.client.search(path, options);
        if (shouldEncrypt) {
            if ((res as ResponseDataDetailed<SearchResult>).data) {
                (res as ResponseDataDetailed<SearchResult>).data.results.forEach(item => {
                    return this.decryptFileStat(item);
                });
                return res;
            } else {
                (res as SearchResult).results.forEach(item => {
                    return this.decryptFileStat(item);
                });
                return res;
            }
        } else {
            return res;
        }
    }
    async unlock(path: string, token: string, options?: WebDAVMethodOptions): Promise<void> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await this.client.unlock(path, token, options);
    }

    private shouldEncrypt(): boolean {
        return this.globalEncrypt;
    }

    private encryptFilename(filename: string): string {
        const encrypted = this.encrypt(new TextEncoder().encode(filename));
        return Array.from(encrypted)
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    }

    private decryptFilename(encryptedFilename: string): string {
        const buffer = new Uint8Array(
            encryptedFilename.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
        );
        return new TextDecoder().decode(this.decrypt(buffer));
    }
    private encryptPath(path: string): string {
        return path
            .split("/")
            .filter(x => x != "")
            .map(x => this.encryptFilename(x))
            .join("/");
    }

    private decryptPath(path: string): string {
        return path
            .split("/")
            .filter(x => x != "")
            .map(x => this.decryptFilename(x))
            .join("/");
    }
    private decryptFileStat(filestat: FileStat) {
        filestat.basename = this.decryptFilename(filestat.basename);
        filestat.filename = this.decryptPath(filestat.filename);
        return filestat;
    }
    private encrypt(data: Uint8Array): Uint8Array {
        // Simplified encryption for demonstration. In a real-world scenario, use a proper encryption library.
        return data;
    }

    private decrypt(data: Uint8Array): Uint8Array {
        // Decryption is the same as encryption in this simplified example
        return data;
    }

    async getFileContents(
        filename: string,
        options?: GetFileContentsOptions
    ): Promise<
        string | webdav.BufferLike | webdav.ResponseDataDetailed<string | webdav.BufferLike>
    > {
        const shouldEncrypt = this.shouldEncrypt();
        if (shouldEncrypt) {
            const path = this.encryptPath(filename);

            let content = await this.client.getFileContents(path, {
                ...options,
                format: "binary"
            });
            let newData: Uint8Array = undefined;
            // if (typeof content === "string") {
            //     newData = new TextEncoder().encode(content);
            // } else
            // console.log(typeof content);
            if (content instanceof ArrayBuffer) {
                newData = new Uint8Array(content);
            } else if (content instanceof Uint8Array) {
                newData = content;
            } else if (Buffer.isBuffer(content)) {
                newData = new Uint8Array(
                    (content as Buffer).buffer.slice(
                        (content as Buffer).byteOffset,
                        (content as Buffer).byteOffset + (content as Buffer).byteLength
                    )
                );
            } else {
                throw new Error("Unsupported data type");
            }
            const decryptedContent = this.decrypt(newData);

            return options?.format === "text"
                ? new TextDecoder().decode(decryptedContent)
                : isWeb() || isReactNative()
                  ? decryptedContent
                  : Buffer.from(await decryptedContent.buffer);
        } else {
            return await this.client.getFileContents(filename, options);
        }
    }

    async putFileContents(
        filename: string,
        data: string | webdav.BufferLike | Readable,
        options?: PutFileContentsOptions
    ): Promise<boolean> {
        const shouldEncrypt = this.shouldEncrypt();
        if (shouldEncrypt) {
            filename = this.encryptPath(filename);
            let newData: any = undefined;
            if (data instanceof Readable) {
                let that = this;
                // 创建一个转换流来加密数据
                const encryptStream = new stream.Transform({
                    transform(chunk, encoding, callback) {
                        // 使用 crypto-js 加密数据
                        const encrypted = that.encrypt(chunk);
                        // 将加密后的数据推送到输出流
                        this.push(encrypted);
                        callback();
                    }
                });
                const encryptedStream = data.pipe(encryptStream);
                return await this.client.putFileContents(filename, encryptedStream, options);
            } else {
                if (typeof data === "string") {
                    newData = new TextEncoder().encode(data);
                } else if (data instanceof ArrayBuffer) {
                    newData = new Uint8Array(data);
                } else if (data instanceof Uint8Array) {
                    newData = data;
                } else if (Buffer.isBuffer(data)) {
                    newData = (data as Buffer).buffer.slice(
                        (data as Buffer).byteOffset,
                        (data as Buffer).byteOffset + (data as Buffer).byteLength
                    );
                } else {
                    throw new Error("Unsupported data type");
                }

                let content = this.encrypt(newData).buffer;
                return await this.client.putFileContents(filename, content, options);
            }
        } else {
            return await this.client.putFileContents(filename, data, options);
        }
    }
    async partialUpdateFileContents(
        path: string,
        start: number,
        end: number,
        data: string | BufferLike | Readable,
        options?: WebDAVMethodOptions
    ): Promise<void> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        if (shouldEncrypt) {
            if (data instanceof Readable) {
                let that = this;
                // 创建一个转换流来加密数据
                const encryptStream = new stream.Transform({
                    transform(chunk, encoding, callback) {
                        // 使用 crypto-js 加密数据
                        const encrypted = that.encrypt(chunk);
                        // 将加密后的数据推送到输出流
                        this.push(encrypted);
                        callback();
                    }
                });
                const encryptedStream = data.pipe(encryptStream);
                return await this.client.partialUpdateFileContents(
                    path,
                    start,
                    end,
                    encryptedStream,
                    options
                );
            } else {
                let newData: Uint8Array = undefined;
                if (typeof data === "string") {
                    newData = new TextEncoder().encode(data);
                } else if (data instanceof ArrayBuffer) {
                    newData = new Uint8Array(data);
                } else if (data instanceof Uint8Array) {
                    newData = data;
                } else {
                    throw new Error("Unsupported data type");
                }
                let content = shouldEncrypt ? this.encrypt(newData).buffer : data;
                return await this.client.partialUpdateFileContents(
                    path,
                    start,
                    end,
                    content,
                    options
                );
            }
        } else {
            return await this.client.partialUpdateFileContents(path, start, end, data, options);
        }
    }
    async getDirectoryContents(
        path: string,
        options?: GetDirectoryContentsOptions
    ): Promise<webdav.FileStat[] | webdav.ResponseDataDetailed<webdav.FileStat[]>> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        const contents = await this.client.getDirectoryContents(path, options);

        if (shouldEncrypt) {
            if ((contents as ResponseDataDetailed<FileStat[]>).data) {
                (contents as ResponseDataDetailed<FileStat[]>).data.forEach(item => {
                    return this.decryptFileStat(item);
                });
                return contents as ResponseDataDetailed<FileStat[]>;
            } else {
                return (contents as FileStat[]).map(item => {
                    return this.decryptFileStat(item);
                });
            }
        } else {
            return contents as FileStat[];
        }
    }

    async createDirectory(path: string, options?: CreateDirectoryOptions): Promise<void> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await this.client.createDirectory(path, options);
    }

    async customRequest(url: string, options?: RequestOptionsCustom): Promise<Response> {
        return await this.client.customRequest(url, options);
    }

    async deleteFile(path: string, options?: RequestOptions): Promise<void> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await (this as any).client.deleteFile(path, options);
    }

    async moveFile(pathFrom: string, pathTo: string, options?: MoveFileOptions): Promise<void> {
        const shouldEncrypt = this.shouldEncrypt();
        const fromPath = shouldEncrypt ? this.encryptPath(pathFrom) : pathFrom;
        const toPath = shouldEncrypt ? this.encryptPath(pathTo) : pathTo;
        return await this.client.moveFile(fromPath, toPath, options);
    }

    async copyFile(pathFrom: string, pathTo: string, options?: CopyFileOptions): Promise<void> {
        const shouldEncrypt = this.shouldEncrypt();
        const fromPath = shouldEncrypt ? this.encryptPath(pathFrom) : pathFrom;
        const toPath = shouldEncrypt ? this.encryptPath(pathTo) : pathTo;
        return await this.client.copyFile(fromPath, toPath, options);
    }

    async stat(
        path: string,
        options?: StatOptions
    ): Promise<FileStat | ResponseDataDetailed<FileStat>> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await this.client.stat(path, options);
    }

    async exists(path: string, options?: RequestOptions): Promise<boolean> {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return await (this as any).client.exists(path, options);
    }

    getFileDownloadLink(path: string): string {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return this.client.getFileDownloadLink(path);
    }

    getFileUploadLink(path: string): string {
        const shouldEncrypt = this.shouldEncrypt();
        path = shouldEncrypt ? this.encryptPath(path) : path;
        return this.client.getFileUploadLink(path);
    }

    async getQuota(
        options?: GetQuotaOptions
    ): Promise<DiskQuota | ResponseDataDetailed<DiskQuota>> {
        return this.client.getQuota(options);
    }

    getHeaders(): Headers {
        return this.client.getHeaders();
    }

    setHeaders(headers: Headers): void {
        this.client.setHeaders(headers);
    }
}

export function createClient(remoteURL: string, options: EncryptedWebDAVClientOptions = {}) {
    return new EncryptedWebDAVClient(remoteURL, options);
}
export {
    WebDAVClient,
    FileStat,
    WebDAVClientOptions,
    RequestOptions,
    Response,
    AuthType,
    GetDirectoryContentsOptions,
    CreateDirectoryOptions,
    PutFileContentsOptions,
    ResponseDataDetailed,
    DiskQuota,
    BufferLike,
    CreateReadStreamOptions,
    CreateWriteStreamCallback,
    CreateWriteStreamOptions,
    DAVCompliance,
    LockOptions,
    LockResponse,
    SearchOptions,
    SearchResult,
    WebDAVMethodOptions,
    GetFileContentsOptions,
    RequestOptionsCustom,
    MoveFileOptions,
    CopyFileOptions,
    StatOptions,
    GetQuotaOptions,
    Headers,
    getPatcher,
    parseStat,
    parseXML
};
