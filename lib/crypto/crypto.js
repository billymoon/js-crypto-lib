crypto = (function(){

  RawDeflate = require("../rawdeflate/rawdeflate")
  CryptoJS = require("../cryptojs/cryptojs")
  RSA = require("../rsa/rsa")
  asn1 = require("../asn1/asn1")

  var crypto = {}

  /*
  openssl genrsa -out key.pem
  openssl rsa -in key.pem -pubout > key.pub
  openssl rsa -pubin -modulus -noout < key.pub
  #
  # to decrypt mess.enc (message encrypted via javascript)
  cat mess.enc | openssl base64 -d | openssl rsautl -inkey key.pem -decrypt
  */

  /**
   * packs the data up - encrypting with AES,
   * storing the key with RSA, and compressing
   * with DEFLATE.
   * 
   * @param text {String} the text to be stored (JSON should be stringified before storing)
   * @param password {String} password to encrypt with
   * @param private_key {String} private key provided in definition file
   * @param exponent {String} (optional - defaults to "10001") exponent of public key (usually 10001, can be found with `openssl rsa -pubin -text -noout < key.pub`)
   */
  crypto.pack = function(text,password,private_key,exponent){
 
      // create the return object
      var ret = {}

      // call rsa enc using password as text to encrypt, and providing private key
      ret.password = crypto.rsa.enc(password,private_key,exponent);
      
      // pack with DEFLATE
      var c = crypto.deflate(text)
      
      // encrypt data using AES
      ret.message = CryptoJS.AES.encrypt(c,password).toString()
      
      // return a stringified version of the packed object
      // { password:"RSA-Encrypted-Password", message:"AES-Encrypted-Message-Text" }
      return JSON.stringify(ret)
  }

  /**
   * wrapper for RSA library encryption and decryption functions
   * 
   * crypto.rsa.enc
   * @param text {String} text to be encrypted (often a password, to be used in AES encryption)
   * @param private_key {String} private key (used to encrypt text with)
   * @param exponent {String} exponent of public key
   */
  crypto.rsa = {
    enc: function(text,private_key,exponent){ exponent = exponent || "10001";

      var mod = asn1(private_key)[0]
      // store password using RSA and provided mod from public key
      var rsa = new RSA.Key();
      rsa.setPublic(mod, exponent);
      var res = rsa.encrypt(text);
      if(res){
          return RSA.linebrk(RSA.hex2b64(res), 64);
      } else {
          console.warn("There was an error storing the password")
      }

    },
    dec: function(ciphertext,private_key){
      var rsa = new RSA.Key(),
      key_vals = asn1(private_key),
      decrypted;
      dr = {
        n:key_vals[0],
        e:key_vals[1],
        d:key_vals[2],
        p:key_vals[3],
        q:key_vals[4],
        dmp1:key_vals[5],
        dmq1:key_vals[6],
        coeff:key_vals[7],
      }
      rsa.setPrivateEx(dr.n, dr.e, dr.d, dr.p, dr.q, dr.dmp1, dr.dmq1, dr.coeff);
      var res = rsa.decrypt(RSA.b64tohex(ciphertext))
      if(res == null) {
        return "*** Invalid Ciphertext ***";
      } else {
        return res;
      };
    }
  }

  /**
   * inflates deflated text
   * 
   * @param text {String} packed data
   */
  crypto.inflate = function(text){
    return RawDeflate.inflate(text);
  }

  /**
   * deflates plain text
   * 
   * @param text {String} arbitrary data
   */
  crypto.deflate = function(text){
    return RawDeflate.deflate(text);
  }

  /**
   * unpacks the data that was packed with the `pack` function.
   * 
   * @param p {String} password used to encrypt with
   * @param d {String} packed data
   */
  crypto.unpack = function(d, p){

      // get the javascript object back from passed data string
      var o = JSON.parse(d)
      
      // decrypt the message using provided password
      var plain = CryptoJS.AES.decrypt(o.message,p).toString(CryptoJS.enc.Utf8)
      
      // inflate the compressed data
      var inflated = crypto.inflate(plain)
      
      // return the plain text string
      return inflated

  }

  /**
   * decrypts the password encrypted during the `pack` operation
   * 
   * @param packed {String} packed object
   * @param private_key {String} private key to decrypt with
   */
  crypto.decrypt = function(packed,private_key){
    ciphertext = JSON.parse(packed).password
    if(ciphertext.length == 0) {
      console.log("No Ciphertext - encrypt something first");
      return;
    }
    var decrypted = this.rsa.dec(ciphertext,private_key);
    return this.unpack(packed,decrypted)
  }

  /**
   * generates RSA keypair
   * 
   * @param bits {Number} keylength in bits. should be power of 2, recommend min 512, max 2048
   * @return {Object} object containing `public` and `private` properties, containing generated keys
   */
  crypto.generate_keys = function(bits,e){ e = e || "10001"; bits = bits || 512

    function generate_numbers(dr){

      var rsa = new RSA.Key();

      rsa.generate(parseInt(dr.bits),dr.e);

      dr.n = rsa.n.toString(16);
      dr.d = rsa.d.toString(16);
      dr.p = rsa.p.toString(16);
      dr.q = rsa.q.toString(16);
      dr.dmp1 = rsa.dmp1.toString(16);
      dr.dmq1 = rsa.dmq1.toString(16);
      dr.coeff = rsa.coeff.toString(16);

      return(dr)

    }

    var encode_data = function(data_array){
      
      var data = ""
      
      // loop through all the numbers
      for(i in data_array){
        var item = data_array[i]

        item = item.split(/[\r\n]+/).join("")

        // if the item has an odd number of characters, then pad with `0`
        if(item.length % 2){ item = "0"+item }

        // if the first binary bit is 1 (if the first hex pair is greater than 127)
        // add a `00` prefix, as ASN1 demands
        if(parseInt(item.match(/^../),16) > 127){ item = "00"+item }

        // calculate the length
        var len = (item.length/2).toString(16)
        if((len.length % 2)){ len = "0"+len }
        if(parseInt(len,16)>127){ len = (128+(len.length/2)).toString(16)+len }

        // build data string, the `02` is ASN1 code for string
        data += "02"+len+item

        // can check all the input data here
        // console.log("02", len, item)
      }

      return data

    }

    var get_datalength = function(data){
      // calculate the length of all the data
      var datalen = (data.length/2).toString(16)
      // add leading `0` if required to ensure hex pairs
      if(datalen.length % 2 == 1){ datalen = "0"+datalen }

      // set the extra bits to define the length if required, or make it empty
      var exlen = parseInt(datalen,16) >= 128 ? (datalen.length/2 + 128).toString(16) : ''

      return exlen+datalen
    }

    // generate key numbers
    var key = generate_numbers({ bits:bits, e:e })

    var keys = {}

    ////////// PRIVATE KEY PART ///////////

    // set numbers for private key
    var numbers = ['00',key.n,key.e,key.d,key.p,key.q,key.dmp1,key.dmq1,key.coeff]

    var data = encode_data(numbers)

    // create the full data string, by adding the header
    data = "30"+get_datalength(data)+data

    // encode the data
    var encoded = RSA.hex2b64(data)

    // split it into lines no longer than 64 characters
    var lines = encoded.match(/.{1,64}/g)

    // add the armour
    lines.unshift("-----BEGIN RSA PRIVATE KEY-----")
    lines.push("-----END RSA PRIVATE KEY-----")

    // join it all together
    var generated_key = lines.join("\n")

    // assign the generated key
    keys.private = generated_key

    //////////// PUBLIC KEY SECTION ////////////////

    // get the modulus, and public exponent from the generated numbers
    var parts = [numbers[1],numbers[2]]

    // encode the data
    var data = encode_data(parts)

    // add a header for the data
    data = "30"+get_datalength(data)+data

    // added seemingly arbitrarily to signify number of wasted bits
    // as part of a bitstring header
    data = "00"+data
    data = "03"+get_datalength(data)+data

    // bring the noise, the generic header, identifying the key type
    data = "300D06092A864886F70D0101010500"+data

    // wrap it all up in a final header
    data = "30"+get_datalength(data)+data

    // encode the data
    var encoded = RSA.hex2b64(data)

    // split it into lines no longer than 64 characters
    var lines = encoded.match(/.{1,64}/g)

    // add the armour
    lines.unshift("-----BEGIN PUBLIC KEY-----")
    lines.push("-----END PUBLIC KEY-----")

    // join it all together
    var generated_pub = lines.join("\n")

    // assign the generated key
    keys.public = generated_pub

    //////////////// Return the keys //////////
    return keys

  },

  /**
   * AES wrapper function for CryptoJS
   *
   */
  crypto.AES = {
    enc: function(plain,pass){
      return CryptoJS.AES.encrypt(plain,pass).toString()
    },
    dec: function(crypt,pass){
      return CryptoJS.AES.decrypt(crypt,pass).toString(CryptoJS.enc.Utf8)    
    }
  }

  return crypto

})()

if(typeof module != "undefined"){ module.exports = crypto }