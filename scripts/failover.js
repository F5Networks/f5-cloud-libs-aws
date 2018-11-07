#!/usr/bin/env node

/**
 * Copyright 2018 F5 Networks, Inc.
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

'use strict'
const parser = require('commander');
const fs = require('fs');
const q = require('q');
var AWS = require('aws-sdk');

const f5CloudLibs = require('@f5devcentral/f5-cloud-libs');
const util = f5CloudLibs.util;
const Logger = f5CloudLibs.logger;

// Parse command line arguments
parser
    .version('1.0.0')
    .option('--log-level [type]', 'Specify the log level', 'info')
    .option('--log-file [type]', 'Specify the log file location', '/var/log/cloud/aws/failover.log')
    .option('--tag-key [type]', 'Specify the key for the tag', 'f5_deployment')
    .option('--tag-value [type]', 'Specify the value of the tag', '')
    .option('--vip-allocation-id [type]', 'Specify the Allocation ID of the Virtual IP address', '')
    .option('--associate-eni [type]', 'Specify the ENI of the network interface to associate with', '')
    .option('--peer-instance-id [type]', 'Specify instance ID of the peer instance', '')
    .option('--password-uri [type]', 'Specify URI password of the BIG-IQ', '')
    .parse(process.argv);
const loggerOptions = {logLevel: parser.logLevel, fileName: parser.logFile, console: true};
const logger = Logger.getLogger(loggerOptions);
const BigIp = f5CloudLibs.bigIp;
const bigip = new BigIp({logger});

// Initialize global vars
const IID_FILE_PATH = '/shared/vadc/aws/iid-document';
const TAG_KEY = parser.tagKey;
let TAG_VALUE = parser.tagValue;
let AllocationEipID = parser.vipAllocationId;
let PeerInstanceId = parser.peerInstanceId;
let passwordUri = parser.passwordUri;

let networkInterfaceIdIdToAssociate = parser.associateEni;
let associationIdToDisassociate;
let allocationIdToAssociate;

let NetworkAddresses = [];
let ec2;
let curIidData;
let associateRequired = false;
let initialized = false;
let bigIqPasswordData = {};

/**
 * Determine PRIMARY state
 * 
 * @return {Promise} A promise which is resolved upon PRIMARY state of the current instance is determined
 */
function isPrimaryInstance() {
    const deferred = q.defer();
    util.readData(passwordUri,
        true)
    .then((uriData) => {
        bigIqPasswordData = util.lowerCaseKeys(
            JSON.parse(uriData.trim()));
        console.log("BigIQ password: ", bigIqPasswordData.admin);
        bigip.init(
            'localhost',
            'admin',
            bigIqPasswordData.admin,
            {
                port: '443'
            }
        )
    })
    .then(() => {
        return q.all([
            bigip.list('/shared/failover-state')
        ]);
    })
    .then((results) => {
        console.log("Failover state:", results[0].nodeRole);
        deferred.resolve();
    })
    .catch((err) => {
        logger.info(`Error getting failover state: ${err}`);
        deferred.reject(err);
    })
    return deferred.promise;
}

/** 
 * Config AWS
 * 
 * @param {String} reg - Region to deploy Azure ARM
 * 
 * @return {Promise} A promise which is resolved upon AWS configuration completion
 */
function configureAWS() {
    const deferred = q.defer();
    AWS.config.getCredentials(function(err) {
        if (err) {
            deferred.reject(err);
        }
        else {
            const creds = {
                accessKey: AWS.config.credentials.accessKeyId,
                secretKey: AWS.config.credentials.secretAccessKey
            };
            deferred.resolve(creds);
        }
    });
    return deferred.promise;
}

/**
 * Get data from iid doc (generated by AWS)
 * 
 * @return A promise which is resolved upon data is read from iid doc
 */
function getIidDoc() {
    const deferred = q.defer();
    fs.readFile(IID_FILE_PATH, function(err, data) {
        if (err) {
            logger.error(`Error reading IID file: ${err}`);
            deferred.reject(err);
        }
        else {
            console.log("IID data: ", data.toString());
            deferred.resolve(JSON.parse(data.toString()));
        }
    });
    return deferred.promise;
}

/**
 * Get tag information of an Elastic IP
 * 
 * @param {String} tag_key - Key of the tag
 * @param {String} tag_value - Value of the tag
 * 
 * @returns {Promise} A promise which is resolved upon tag information is retrieved
 */
function getTagInfo(tag_key, tag_value) {
    const deferred = q.defer();
    var params = {
        Filters: [
            {
                Name: "key",
                Values: [tag_key]
            },
            {
                Name: "value",
                Values: [tag_value]
            },
            {
                Name: "resource-type",
                Values: ["elastic-ip"]
            }
        ]
    };
    ec2.describeTags(params, function(err, data) {
        if (err) {
            logger.error(`Error describe tag: ${err}`);
            deferred.reject(err);
        }
        else {
            deferred.resolve(data);
        }
    });
    return deferred.promise;
}
/**
 * Tag an Elastic IP address if needed
 * 
 * @param {Array} tagData - retrieved tag information 
 * 
 * @return {Promise} A promise which is resolved upon matching tag is retrieved or added
 * 
 */
function addTag(tagData) {
    const deferred = q.defer();
    var num_tags = Object.keys(tagData.Tags).length;
    if (num_tags == 0) {
        logger.info('Tag not found, need to tag resource');
        var create_tag_params = {
        Resources: [
            AllocationEipID
        ],
        Tags: [
            {
                Key: TAG_KEY,
                Value: TAG_VALUE
            }
        ]};

        ec2.createTags(create_tag_params, function(err, data) {
        if (err) {
            logger.error(`Error adding tag: ${err}`);
            deferred.reject(err);
        }
        else {
            deferred.resolve(data);
        }});
    }
    else if (num_tags == 1) {
        logger.info(`Tag found, no need to tag resource: ${tagData.Tags[0]}`);
        deferred.resolve(tagData);
    }
    else
    {
        logger.error('Error: multiple tags');
        deferred.reject(tagData.Tags);
    }
    return deferred.promise;
}

/**
 *  Get  network addresses
 */
function getNetworkAddresses(curInstanceId, peerInstanceId)
{
    const deferred = q.defer();
    var describe_addresses_params = {
        Filters: [{Name: "domain", Values: ["vpc"]}
                  ]
      };

    ec2.describeAddresses(describe_addresses_params, function(err, data) {
    if (err) {
        logger.error(`Error getting network addresses: ${err.stack}`);
        deferred.reject(err);
    }
    else {
        for (let value of data["Addresses"]) {
            var instanceId = value.InstanceId;
            if (instanceId != undefined && (instanceId == curInstanceId || instanceId == peerInstanceId)) {
                NetworkAddresses.push(value);
            }
        }
        for (let addr of NetworkAddresses) {
            var tag = addr.Tags;
            if ((tag != undefined) && (tag.length == 1) && (tag[0].Key == TAG_KEY) && (tag[0].Value == TAG_VALUE)) {
                if (curInstanceId != addr.InstanceId)
                {
                    associationIdToDisassociate = addr.AssociationId;
                    allocationIdToAssociate = addr.AllocationId;
                    associateRequired = true;
                }
            }
        }
        deferred.resolve();
    }
    });
    return deferred.promise;
}

/**
 * Disassociate an IP address
 */
function disassociateIpAddress() {
    const deferred = q.defer();
    if (associateRequired) {
        logger.info('Disassociate Virtual IP address');
        var params = {
            AssociationId: associationIdToDisassociate
        };
        ec2.disassociateAddress(params, function(err, data) {
            if (err) {
                logger.error(`Fail to disassociate IP address: ${err}`);
                deferred.reject(err);
            }
            else {
                deferred.resolve();
            }
        });
    }
    else {
        deferred.resolve();
    }
    return deferred.promise;
}

/**
 * Associate an IP address
 */
function associateIpAddress() {
    const deferred = q.defer();
    if (associateRequired) {
        logger.info('Associate Virtual IP address');
        var params = {
            AllocationId: allocationIdToAssociate, 
            NetworkInterfaceId: networkInterfaceIdIdToAssociate
        };
        ec2.associateAddress(params, function(err, data) {
            if (err) {
                logger.error(`Fail to associate IP address: ${err}`);
                deferred.reject(err);
            }
            else {
                deferred.resolve();
            }
        });
    }
    else {
        deferred.resolve();
    }
    return deferred.promise;
}

/**
 * Initialize resources
 * 
 * @param {String} reg - Region to deploy Azure ARM
 * 
 * @return {Promise} A promise which is resolved upon initialization completion
 * 
 */
function init() {
    const deferred = q.defer();
    Promise.all([
        getIidDoc(),
        configureAWS()
    ])
    .then((data) => {
        curIidData = data[0];
        console.log("Access Key: ", data[1].accessKey);
        console.log("Secret Key: ", data[1].secretKey);
        AWS.config.update({region: curIidData.region});
        ec2 = new AWS.EC2({apiVersion: '2016-11-15'});
        initialized = true;
        deferred.resolve();
    })
    .catch((err) => {
        logger.error(`Failed to initialize AWS configuration: ${err}`);
        deferred.reject();
    })
    return deferred.promise;
}

 /**
  * Perform failover
  *  
  */
function failover() {
    init()
    .then(() => {
        return getTagInfo(TAG_KEY, TAG_VALUE);
    })
    .then ((tagData) => {
        logger.info("Create tag If neccessary");
        return addTag(tagData);
    })
    .then((createdTag) => {
        logger.info("Tag added successfully", createdTag.Tags[0]);
        return getNetworkAddresses(curIidData.instanceId, PeerInstanceId);
    })
    .then(()=>{
        return disassociateIpAddress();
    })
    .then(()=>{
        return associateIpAddress();
    })
    .catch(error => {
        logger.info(`Failover failed: ${error}`);
    });
}

/** 
 * Test failover
 */
function test_failover() {
    isPrimaryInstance()
    .then(() => {
        return init();
    })
    .then(() => {
        return getTagInfo(TAG_KEY, TAG_VALUE);
    })
    .catch(error => {
        console.log("Failover failed", error);
    })
}

test_failover();
// failover();
