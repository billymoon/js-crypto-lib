// require the base library
var crypto = require("./lib/crypto/crypto")

/* horrific hack for console javascript
 * suppress alerts from rsa and rawdeflate libraries
 * makes all alerts log to console instead
 */
// alert = console.log

// simple console log utility function
var print = function(message, title){
    if(!title){ title = "New Section"; }
    console.log("== "+title+" ==");
    console.log(message);
    console.log("");
}

var keys = crypto.generate_keys();
print(keys.public, "public key");
print(keys.private, "private key");

var plain = "just some sample text";
var password = "opensesame";

var cypher = crypto.AES.enc(plain,password);
print(cypher, "encrypted message (AES)");

var decrypted = crypto.AES.dec("U2FsdGVkX1/1uzsMtEvYgubmfEc5Yc7u2NBkVppg5PsjWphv+O0iar0jZNpRQ3BM",password);
print(decrypted, "decrypted message (AES)");

var packed = crypto.pack(plain,password,keys.private);
print(packed, "all packed up");

var unpacked = crypto.unpack(packed,password);
print(unpacked, "unpacked");

var decrypted = crypto.decrypt(packed,keys.private);
print(decrypted, "decrpted");

var rsacrypted = crypto.rsa.enc(password,keys.private);
print(rsacrypted, "encrypted (RSA)");

var rsadecrypted = crypto.rsa.dec(rsacrypted,keys.private);
print(rsadecrypted, "decrypted (RSA)");

var deflated = crypto.deflate(keys.private);
print(deflated.length+" jibberish characters", "deflated private key");

var inflated = crypto.inflate(deflated);
print(inflated.length+" coherent characters\n"+inflated, "inflated from deflated private key");