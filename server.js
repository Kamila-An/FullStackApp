import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());


// Step 3: RSA Keys

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
});
console.log("Step 3: RSA key pair generated");

const sessions = new Map();

// Step 4: Public Key

app.get("/publicKey", (req, res) => {
    res.json({
        publicKey: publicKey.export({ type: "pkcs1", format: "pem" })
    });
});


// Step 5: Session Key

app.post("/session", (req, res) => {
    const encryptedKey = Buffer.from(req.body.encryptedKey, "base64");

    const sessionKey = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        },
        encryptedKey
    );

    const sessionId = crypto.randomBytes(16).toString("hex");
    sessions.set(sessionId, sessionKey);

    console.log("New session created:", sessionId);
    res.json({ sessionId });
});


// Steps 8–10

app.post("/message", (req, res) => {
    const { sessionId, ciphertext, iv, authTag, hmac } = req.body;
    const key = sessions.get(sessionId);

    if (!key) {
        return res.status(400).json({ error: "Invalid session" });
    }

    // Step 8: HMAC verification
    const expectedHmac = crypto
        .createHmac("sha256", key)
        .update(ciphertext)
        .digest("base64");

    if (!crypto.timingSafeEqual(
        Buffer.from(expectedHmac),
        Buffer.from(hmac)
    )) {
        return res.json({ validHMAC: false, message: "HMAC verification failed" });
    }

    // Step 9: AES Decryption
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(authTag, "base64"));

    let decrypted = decipher.update(Buffer.from(ciphertext, "base64"));
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    // Step 10: Deserialize
    const student = JSON.parse(decrypted.toString());

    console.log("Received valid message:");
    console.log(student);

    res.json({
        validHMAC: true,
        message: "Message decrypted and verified",
        student
    });
});

// ------------------
app.listen(8080, () => {
    console.log("Server listening on http://localhost:8080");
});
