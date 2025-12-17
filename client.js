import crypto from "crypto";
import fetch from "node-fetch";

// Student class

class Student {
    constructor(id, name, major) {
        this.id = id;
        this.name = name;
        this.major = major;
    }
}

// Step 1: Serialize

const student = new Student(1234, "Kate An", "Business");
const studentJSON = JSON.stringify(student);
console.log(`Step 1: Student serialized to JSON: ${studentJSON}`);

// Step 4: Get public key

const pkResp = await fetch("http://localhost:8080/publicKey");
const { publicKey } = await pkResp.json();
console.log("Step 4: Public key received");


// Step 5: Session key

const sessionKey = crypto.randomBytes(32);

const encryptedKey = crypto.publicEncrypt(
    {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
    },
    sessionKey
);

const sessionResp = await fetch("http://localhost:8080/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        encryptedKey: encryptedKey.toString("base64")
    })
});

const { sessionId } = await sessionResp.json();
console.log(`Step 5: Session established, sessionID = ${sessionId}`);


// Step 6: AES Encrypt

const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv);

let encrypted = cipher.update(studentJSON);
encrypted = Buffer.concat([encrypted, cipher.final()]);
const authTag = cipher.getAuthTag();
console.log("Step 6: Message encrypted");


// Step 7: HMAC

const hmac = crypto
    .createHmac("sha256", sessionKey)
    .update(encrypted.toString("base64"))
    .digest("base64");
console.log("Step 7: HMAC generated");

// Send message

const msgResp = await fetch("http://localhost:8080/message", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        sessionId,
        ciphertext: encrypted.toString("base64"),
        iv: iv.toString("base64"),
        authTag: authTag.toString("base64"),
        hmac
    })
});

const result = await msgResp.json();
console.log("Server response:");
console.log(result);
