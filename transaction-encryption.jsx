import React, { Component } from 'react';
import CryptoJS from 'crypto-js';
import JSEncrypt from 'jsencrypt';
import { CryptoService } from '../services/crypto-service.jsx';
//import other components here

export class TransactionEncryption extends Component {

    constructor() {
        super();
        this.cryptoservice = new CryptoService();
        this.user = { userId: 'd41cd772-cb57-412c-a864-6e40b2bd3e12' };
        this.state = { type: 'payment', amount: 100, number: '123-456-789-000', securitycode: '123' ,log:''};
    }

    doTransaction = () => {
        this.cryptoservice.getUserPublicKey(this.user)
            .then((resUser) => {
                this.log("RSA public key[base64]: " +  resUser.data.rsaPublicKey);

                let transaction = { type: this.state.type, amount: this.state.amount, creditcard: { number: this.state.number, securitycode: this.state.securitycode } };

                //generate AES key
                var secretPhrase = CryptoJS.lib.WordArray.random(16);
                var salt = CryptoJS.lib.WordArray.random(128 / 8);
                //aes key 128 bits (16 bytes) long
                var aesKey = CryptoJS.PBKDF2(secretPhrase.toString(), salt, {
                    keySize: 128 / 32
                });
                //initialization vector - 1st 16 chars of userId
                var iv = CryptoJS.enc.Utf8.parse(this.user.userId.slice(0, 16));
                var aesOptions = { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7, iv: iv };
                var aesEncTrans = CryptoJS.AES.encrypt(JSON.stringify(transaction), aesKey, aesOptions);

                this.log(`Transaction: ${JSON.stringify(transaction)}`);
                this.log('AES encrypted transaction [Base64]: ' + aesEncTrans.toString());
                this.log('AES key [hex]: ' + aesEncTrans.key);
                this.log('AES init vector [hex]: ' + aesEncTrans.iv);

                //encrypt AES key with RSA public key
                var rsaEncrypt = new JSEncrypt();
                rsaEncrypt.setPublicKey(resUser.data.rsaPublicKey);
                var rsaEncryptedAesKey = rsaEncrypt.encrypt(aesEncTrans.key.toString());
                this.log('RSA encrypted AES key [base64]: ' + rsaEncryptedAesKey);

                var encryptedTransaction = { userId: this.user.userId, payload: aesEncTrans.toString(), encAesKey: rsaEncryptedAesKey };

                this.cryptoservice.doTransaction(encryptedTransaction);
                showInfoMessage(this, 'System', 'Secure transaction completed.');
            }).catch((error) => {
                console.error(error);
            });
    };

    render() {
        return (
            <div>
            //define UI components here
            </div >
        )
    };
}