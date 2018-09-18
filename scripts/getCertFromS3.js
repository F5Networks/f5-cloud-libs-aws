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

var AWS = require('aws-sdk');
var s3 = new AWS.S3();
var q = require('q');
var mkdirp = require('mkdirp');
var path = '/config/ssl/ssl.key/';
var uri;
var params;
var file;

if (process.argv.length <= 2) {
    console.log("Usage: " + __filename + " <ARN> (Format should be arn:aws:s3:::bucket_name/key_name)");
    process.exit(-1);
}

uri = process.argv[2];

console.log('uri: ' + uri);

if (!uri.startsWith('arn:aws:s3:::')) {
    console.log("Invalid URI. URI should be an S3 arn");
    return q.reject(new Error("Invalid URI. URI should be an S3 arn."));
}

// ARN format is arn:aws:s3:::bucket_name/key_name
parts = uri.split(':::');

// Get the bucket/key
parts = parts[1].split(/\/(.+)/);

// length === 3 because splitting on just the first match leaves an empty string at the end
if (parts.length !== 3) {
    console.log("Invalid ARN. Format should be arn:aws:s3:::bucket_name/key_name");
    return q.reject(new Error("Invalid ARN. Format should be arn:aws:s3:::bucket_name/key_name"));
}

bucket = parts[0];
key = parts[1];

params = {
    Bucket: bucket,
    Key: key
};

console.log(bucket);
console.log(key);

keyDirPath = key.split(/\//);

if (keyDirPath.length > 1) {
    for (var i = 0; i < keyDirPath.length - 1; i++) {
        path += keyDirPath[i] + '/';
    }
    mkdirp(path, function(err) {
        if (err) {
            console.log(err);
        }
    });
}

file = require('fs').createWriteStream(path + keyDirPath[keyDirPath.length - 1]);
s3.getObject(params).createReadStream().pipe(file);
