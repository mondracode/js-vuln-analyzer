var encryptedData = CryptoJS.DES.encrypt("data", "key");
console.log(encryptedData);

var userInputHash = md5(userInput);
if (userInputHash == "5f4dcc3b5aa765d61d8327deb882cf99") {
    console.log("Inseguro: comparación de hash insegura");
}