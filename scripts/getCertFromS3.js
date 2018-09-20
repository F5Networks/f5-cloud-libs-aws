/**
 * Copyright 2017 F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const AWS = require('aws-sdk');

const s3 = new AWS.S3();
const q = require('q');
const mkdirp = require('mkdirp');
const path = require('path');

const filePath = '/config/ssl/ssl.key/';
let parts;

if (process.argv.length <= 2) {
    console.log(`Usage: ${__filename} <ARN> (Format should be arn:aws:s3:::bucket_name/key_name)`);
    process.exit(-1);
}

const uri = process.argv[2];

console.log(`uri: ${uri}`);

const arnRegex = /arn:aws[A-Za-z0-9_-]*:s3:::/;

if (!uri.match(arnRegex)) {
    console.log('Invalid URI. URI should be an S3 arn');
    return q.reject(new Error('Invalid URI. URI should be an S3 arn.'));
}

// ARN format is arn:aws:s3:::bucket_name/key_name
parts = uri.split(':::');

// Get the bucket/key
parts = parts[1].split(/\/(.+)/);

// length === 3 because splitting on just the first match leaves an empty string at the end
if (parts.length !== 3) {
    console.log('Invalid ARN. Format should be arn:aws:s3:::bucket_name/key_name');
    return q.reject(new Error('Invalid ARN. Format should be arn:aws:s3:::bucket_name/key_name'));
}

const params = {
    Bucket: parts[0],
    Key: parts[1]
};

console.log(params.Bucket);
console.log(params.Key);

mkdirp(path.dirname(params.Key), (err) => {
    if (err) {
        console.log(err);
    }
});

const file = require('fs').createWriteStream(filePath + params.Key);

s3.getObject(params).createReadStream().pipe(file);
