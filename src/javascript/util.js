async function encryptWithPublicKey(plaintext, base64PublicKey) {
  const jsEncrypt = new JSEncrypt();
  jsEncrypt.setPublicKey(`-----BEGIN PUBLIC KEY-----
${base64PublicKey}
-----END PUBLIC KEY-----`);
  return jsEncrypt.encrypt(plaintext);
}

const TravisAES = {
  init: () => {
    this._keySize = 256;
    this._ivSize = 128;
    this._iterationCount = 1989;
  },
  generateKey: (salt, passPhrase) => {
    return CryptoJS.PBKDF2(passPhrase, CryptoJS.enc.Hex.parse(salt), {
      keySize: this._keySize / 32,
      iterations: this._iterationCount
    });
  },
  encryptWithIvSalt: (salt, iv, passPhrase, plainText) => {
    let key = TravisAES.generateKey(salt, passPhrase);
    let encrypted = CryptoJS.AES.encrypt(plainText, key, {iv: CryptoJS.enc.Hex.parse(iv)});
    return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
  },
  decryptWithIvSalt: (salt, iv, passPhrase, cipherText) => {
    let key = TravisAES.generateKey(salt, passPhrase);
    let cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(cipherText)
    });
    let decrypted = CryptoJS.AES.decrypt(cipherParams, key, {iv: CryptoJS.enc.Hex.parse(iv)});
    return decrypted.toString(CryptoJS.enc.Utf8);
  },
  encrypt: (passPhrase, plainText) => {
    let iv = CryptoJS.lib.WordArray.random(this._ivSize / 8).toString(CryptoJS.enc.Hex);
    let salt = CryptoJS.lib.WordArray.random(this._keySize / 8).toString(CryptoJS.enc.Hex);
    let cipherText = TravisAES.encryptWithIvSalt(salt, iv, passPhrase, plainText);
    return salt + iv + cipherText;
  },
  decrypt: (passPhrase, cipherText) => {
    let ivLength = this._ivSize / 4;
    let saltLength = this._keySize / 4;
    let salt = cipherText.substr(0, saltLength);
    let iv = cipherText.substr(saltLength, ivLength);
    let encrypted = cipherText.substring(ivLength + saltLength);
    let decrypted = TravisAES.decryptWithIvSalt(salt, iv, passPhrase, encrypted);
    return decrypted;
  },
  getKeySize: () => {
    return this._keySize;
  },
  setKeySize: (value) => {
    this._keySize = value;
  },
  getIterationCount: () => {
    return this._iterationCount;
  },
  setIterationCount: (value) => {
    this._iterationCount = value;
  }
}
TravisAES.init();

async function processResponseInterceptor(response) {
  if (!response || !response.data) return response;
  let data = JSON.parse(response.data);
  if (!data)
    return response;
  // If response is login
  if (data.data && data.data.accessToken) {
    const token = data.data.accessToken;
    localStorage.setItem('token', token);
    const publicKey = data.data.publicKey;
    if (publicKey) {
      localStorage.setItem('publicKey', publicKey);
      let secret = generatePassword(16, false, /[\d\W\w\p]/);
      localStorage.setItem('secret', secret);
      let encryptedSecret = await encryptWithPublicKey(secret, publicKey);
      localStorage.setItem('encryptedSecret', encryptedSecret);
    }
  }
  // If response is secured
  if (response.headers['secure-api'] === 'true') {
    let secret = localStorage.getItem('secret');
    let secureDataResponse = {
      data: data,
      value: JSON.parse(TravisAES.decrypt(secret, data))
    }
    response.body = secureDataResponse;
    response.obj = secureDataResponse;
    response.data = JSON.stringify(secureDataResponse);
    response.text = response.data;
  }
  return response;
}

async function processRequestInterceptor(request) {
  request.headers.Authorization = 'Bearer ' + localStorage.getItem('token');
  let secureApi = request.headers['Secure-Api'];
  if (secureApi == 'true') {
    let secret = localStorage.getItem('secret');
    let encryptedSecret = localStorage.getItem('encryptedSecret');
    request.headers['Secure-Api-Secret'] = encryptedSecret;
    if (request.method !== 'GET') {
      let encryptedData = TravisAES.encrypt(secret, request.body || '');
      request.body = encryptedData;
    }
  }
  return request;
}
