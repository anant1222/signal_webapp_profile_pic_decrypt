'use strict';
const initModels = require("../models/init-models");
var btoa = require('btoa');
const CDN = require('../conf/config').CDN
var toUint8Array = require('base64-to-uint8array')
const sequelize = require('../utils/db-connection').PoolSequelize
const Utils = require('../utils/utils')
const models = initModels(sequelize);
const _crypto = require('crypto');

const decrypt = async function (data) {
            let userUUID = data.userUUID;
            let parametres={
                        attributes:['avatar', 'profile_key'],
                        where:{uuid:userUUID},
                        raw:true
                    }
            let userDetails = await models.profiles.findOne(parametres)
            if(!userDetails){
                return {
                    code: 202,
                    message: 'user not found!',
                    data:{}
                };
            }
            else{
                if(userDetails && !userDetails.avatar){
                    return {
                        code: 205,
                        message: 'user avatar not found!',
                        data:{}
                    };
                }
                if(userDetails && !userDetails.profile_key){
                    return {
                        code: 205,
                        message: 'user profile key not found!',
                        data:{}
                    };
                }
            let cdnURL = `${CDN.hostURL}${userDetails.avatar}`  // make cdn url, for get image data from cdn.
            let fetchCDNData  = await Utils.get(cdnURL,null,false,'CDN') // use axios for get request.
            const data = new Uint8Array(fetchCDNData);
            let masterkey = userDetails.profile_key;   // private master key foe decrypt the profile image.
            var keys = await toUint8Array(masterkey);  // convert key into 8-bit unsigned integers.
            const iv = data.slice(0, 12);  // inital vector
            const ciphertext = data.slice(12, data.byteLength); // get only image data. beside the auth key and all.
            if (keys.byteLength !== 32) {
                // throw new Error('Got invalid length profile key');
                return {
                    code: 412,
                    message: 'Got invalid length profile key',
                    data:''
                };
            }
            if (iv.byteLength !== 12) {
               return { code: 412,
                 message: 'Got invalid length profile iv',
                 data:''
               }
            }
            try {
                const aa = await decryptAesGcm(keys, iv, ciphertext)
                const bb = btoa(aa)   // convert byte to array.
                return {code : '200',message:'Success',data : bb}
            } catch (_) {
                console.log("failed");
            }
            // const key = _crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');
            // AES 256 GCM Mode
            // const decipher = _crypto.createDecipheriv('aes-256-gcm', key, iv);
            // decipher.setAuthTag(tag);

            // encrypt the given text
            // try {
            //     var decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
            // } catch (error) {
            //     console.log(error)
            // }
            return {code : '200',message:'Success',data : decrypted}
        }
}

async function decryptAesGcm(key, iv, ciphertext) {
    return decryptP('aes-256-gcm', { key, ciphertext, iv });
}

async function decryptP(cipherType, {
    key,
    ciphertext,
    iv,
    aad,
}) {
    let decipher;
    let input = Buffer.from(ciphertext);
    if (cipherType === 'aes-256-gcm') {
        const gcm = _crypto.createDecipheriv(cipherType, Buffer.from(key), Buffer.from(iv));
        if (input.length < 16) {
            throw new Error('Invalid GCM ciphertext');
        }
        const tag = input.slice(input.length - 16);
        input = input.slice(0, input.length - 16);
        gcm.setAuthTag(tag);
        if (aad) {
            gcm.setAAD(aad);
        }
        decipher = gcm;
    }
    else {
        strictAssert(aad === undefined, `AAD is not supported for: ${cipherType}`);
        decipher = _crypto.createDecipheriv(cipherType, Buffer.from(key), Buffer.from(iv));
    }
    return Buffer.concat([decipher.update(input), decipher.final()]);
}

module.exports = {
    decrypt
}

