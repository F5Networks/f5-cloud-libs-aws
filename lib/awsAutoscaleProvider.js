/**
 * Copyright 2016-2017 F5 Networks, Inc.
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

var fs = require('fs');
var util = require('util');

var Aws = require('aws-sdk');
var q = require('q');

var cloudUtil;
var AutoscaleProvider;
var BigIp;
var IControl;
var bigIp;
var Logger;
var logger;

const CREDENTIALS_KEY = "credentials/master";
const INSTANCES_FOLDER = "instances/";
const BACKUP_FOLDER = "backup/";
const PUBLIC_KEYS_FOLDER = "public_keys/";

const AWS_RETRY_OPTIONS = {
    httpOptions: { timeout: 120000 },
    maxRetries: 20,
    retryDelayOptions: { base: 300 }
};

// In production we should be installed as a node_module under f5-cloud-libs
// In test, that will not be the case, so use our dev dependency version
// of f5-cloud-libs
try {
    AutoscaleProvider = require('../../../../f5-cloud-libs').autoscaleProvider;
    BigIp = require('../../../../f5-cloud-libs').bigIp;
    IControl = require('../../../../f5-cloud-libs').iControl;
    Logger = require('../../../../f5-cloud-libs').logger;
    cloudUtil = require('../../../../f5-cloud-libs').util;
}
catch (err) {
    AutoscaleProvider = require('f5-cloud-libs').autoscaleProvider;
    BigIp = require('f5-cloud-libs').bigIp;
    IControl = require('f5-cloud-libs').iControl;
    Logger = require('f5-cloud-libs').logger;
    cloudUtil = require('f5-cloud-libs').util;
}

util.inherits(AwsAutoscaleProvider, AutoscaleProvider);

 /**
  * Constructor.
  * @class
  *
  * @param {Ojbect} [options]               - Options for the instance.
  * @param {Object} [options.clOptions]     - Command line options if called from a script.
  * @param {Object} [options.logger]        - Logger to use. Or, pass loggerOptions to get your own logger.
  * @param {Object} [options.loggerOptions] - Options for the logger. See {@link module:logger.getLogger} for details.
  */
function AwsAutoscaleProvider(options) {
    AwsAutoscaleProvider.super_.call(this, options);

    this.features[AutoscaleProvider.FEATURE_MESSAGING] = true;
    this.features[AutoscaleProvider.FEATURE_ENCRYPTION] = true;

    if (options.logger) {
        logger = options.logger;
    }
    else if (options.loggerOptions) {
        options.loggerOptions.module = module;
        logger = Logger.getLogger(options.loggerOptions);
    }
}

/**
 * Initialize class
 *
 * Override for implementation specific initialization needs (read info
 * from cloud provider, read database, etc.). Called at the start of
 * processing.
 *
 * @param {Object}  providerOptions                 - Provider specific options.
 * @param {String}  providerOptions.s3Bucket        - S3 bucket to use for storage.
 * @param {String}  providerOptions.sqsUrl          - SQS queue name.
 * @param {Number}  [providerOptions.mgmtPort]      - BIG-IP management port. Default 443.
 * @param {String}  [providerOptions.roleArn]       - ARN of role to assume.
 * @param {String}  [providerOptions.externalId]    - External Id for role to assume.
 * @param {Object}  [options]                       - Options for this instance.
 * @param {Boolean} [options.autoscale]             - Whether or not this instance will be used for autoscaling.
 *
 * @returns {Promise} A promise which will be resolved when init is complete.
 */
AwsAutoscaleProvider.prototype.init = function(providerOptions, options) {

    this.providerOptions = providerOptions || {};
    options = options || {};

    if (options.autoscale) {
        if (!this.providerOptions.s3Bucket) {
            return q.reject(new Error('AwsAutoscaleProvider requires providerOptions.s3Bucket when used for autoscaling'));
        }

        if (!this.providerOptions.sqsUrl) {
            return q.reject(new Error('AwsAutoscaleProvider requires providerOptions.sqsUrl when used for autoscaling'));
        }
    }

    this.providerOptions.mgmtPort = this.providerOptions.mgmtPort || "443";

    this.nodeProperties = {};
    this.launchConfigMap = {}; // Map of instanceId to launch configuration name
    this.launchConfigurationName = '';

    return getIidDoc()
        .then(function(response) {
            this.nodeProperties.mgmtIp = response.privateIp;
            this.nodeProperties.privateIp = response.privateIp;
            this.nodeProperties.instanceId = response.instanceId;
            this.nodeProperties.region = response.region;

            Aws.config.update({region: this.providerOptions.region || this.nodeProperties.region});
            Aws.config.update(AWS_RETRY_OPTIONS);
            Aws.config.credentials = new Aws.EC2MetadataCredentials(AWS_RETRY_OPTIONS);

            if (this.providerOptions.roleArn && !(this.providerOptions.roleArn === "''" || this.providerOptions.roleArn === '""')) {
                return getTemporaryCredentials(this.providerOptions, this.nodeProperties.instanceId);
            }
        }.bind(this))
        .then(function() {
            this.s3 = new Aws.S3();
            this.ec2 = new Aws.EC2();
            this.autoscaling = new Aws.AutoScaling();
            this.sqs = new Aws.SQS({
                sslEnabled: true
            });

            if (options.autoscale) {
                return getAutoScalingInstanceInfo(this.autoscaling, this.nodeProperties.instanceId);
            }
        }.bind(this))
        .then(function(response) {

            if (options.autoscale) {
                this.nodeProperties.autoscaleGroupId = response.AutoScalingGroupName;
            }

            if (this.clOptions.user && (this.clOptions.password || this.clOptions.passwordUrl)) {
                bigIp = new BigIp({loggerOptions: this.loggerOptions});
                return bigIp.init(
                    'localhost',
                    this.clOptions.user,
                    this.clOptions.password || this.clOptions.passwordUrl,
                    {
                        port: parseInt(this.providerOptions.mgmtPort),
                        passwordIsUrl: typeof this.clOptions.passwordUrl !== 'undefined'
                    });
            }
        }.bind(this))
        .then(function() {
            if (options.autoscale && bigIp) {

                // We also need to write the autoscaleGroupId to BIG-IP to signal it to
                // collect metrics for CloudWatch
                return bigIp.modify(
                    '/tm/sys/autoscale-group',
                    {
                        autoscaleGroupId: this.nodeProperties.autoscaleGroupId
                    }
                );
            }
        }.bind(this))
        .then(function() {
            var deferred;

            if (this.providerOptions.s3Bucket) {
                deferred = q.defer();

                // create the backup folder if it is not there
                listObjects(this.s3, this.providerOptions.s3Bucket, BACKUP_FOLDER)
                    .then(function(data) {
                        if (data.KeyCount !== 0) {
                            logger.silly('Backup folder already exists');
                            deferred.resolve();
                        }
                        else {
                            logger.debug('Creating backup folder');
                            putObject(this.s3, this.providerOptions.s3Bucket, BACKUP_FOLDER)
                                .then(function() {
                                    logger.silly('Backup folder created');
                                    deferred.resolve();
                                })
                                .catch(function(err) {
                                    logger.warn('Error creating backup folder', err);
                                    deferred.reject(err);
                                });
                        }
                    }.bind(this))
                    .catch(function(err) {
                        logger.warn('Error checking for backup folder', err);
                        deferred.reject(err);
                    });

                return deferred.promise;
            }
        }.bind(this));
};

/**
 * Gets data from a provider specific URI
 *
 * URI must be an S3 ARN
 *
 * @param {String} uri - The cloud-specific URI of the resource. In this case, the URI is
 *                       expected to be the ARN of an item in S3
 *
 * @returns {Promise} A promise which will be resolved with the data from the URI
 *                    or rejected if an error occurs.
 */
AwsAutoscaleProvider.prototype.getDataFromUri = function(uri) {
    var bucket;
    var key;
    var parts;

    if (!uri.startsWith('arn:aws:s3:::')) {
        return q.reject(new Error("Invalid URI. URI should be an S3 arn."));
    }

    // ARN format is arn:aws:s3:::bucket_name/key_name
    parts = uri.split(':::');

    // Get the bucket/key
    parts = parts[1].split(/\/(.+)/);

    // length === 3 because splitting on just the first match leaves an empty string at the end
    if (parts.length !== 3) {
        return q.reject(new Error("Invalid ARN. Format should be arn:aws:s3:::bucket_name/key_name"));
    }

    bucket = parts[0];
    key = parts[1];

    return getObject(this.s3, bucket, key)
        .then(function(data) {
            return data.toString();
        })
        .catch(function(err) {
            return q.reject(err);
        });
};

/**
 * Gets the instance ID of this instance
 *
 * @returns {Promise} A promise which will be resolved with the instance ID of this instance
 *                    or rejected if an error occurs;
 */
AwsAutoscaleProvider.prototype.getInstanceId = function() {
    return q(this.nodeProperties.instanceId);
};

/**
 * Gets info for each instance
 *
 * Reports instances which are marked as master and/or visible to the cloud provider
 *
 * @returns {Promise} A promise which will be resolved with a dictionary of instances
 *                    keyed by instance ID. Each instance value should be:
 *
 *                   {
 *                       isMaster: <Boolean>,
 *                       hostname: <String>,
 *                       mgmtIp: <String>,
 *                       privateIp: <String>,
 *                       providerVisible: <Boolean> (does the cloud provider know about this instance)
 *                   }
 */
AwsAutoscaleProvider.prototype.getInstances = function() {
    var deferred = q.defer();
    var params = {
        AutoScalingGroupNames: [this.nodeProperties.autoscaleGroupId]
    };
    var instances = {};
    var awsInstanceIds = [];
    var missingInstanceIds = [];
    var idsToDelete = [];
    var instancesToRevoke = [];
    var instanceId;
    var i;

    // First, get instance list from AWS
    this.autoscaling.describeAutoScalingGroups(params, function(err, data) {
        var autoscalingGroup;

        if (err) {
            logger.error('autoscaling.describeAutoScalingGroups:', err);
            deferred.reject(err);
        }
        else {
            // We need a map of launchConfigruartionName for detecting when a template update has occurred
            autoscalingGroup = data.AutoScalingGroups[0];
            this.launchConfigurationName = autoscalingGroup.LaunchConfigurationName;
            logger.debug('getInstances: Number of instances in autoscale group:', autoscalingGroup.Instances.length);
            logger.debug('getInstances: launchConfigurationName:', this.launchConfigurationName);
            autoscalingGroup.Instances.forEach(function(instance) {
                instanceId = instance.InstanceId;
                logger.debug('getInstances: instance:', instanceId);
                this.launchConfigMap[instanceId] = instance.LaunchConfigurationName;
                awsInstanceIds.push(instanceId);
            }.bind(this));

            // Now get info from our database
            getInstancesFromDb(this.s3, this.providerOptions.s3Bucket)
                .then(function(registeredInstances) {
                    var registeredInstanceIds = Object.keys(registeredInstances);
                    var instance;

                    for (i = 0; i < registeredInstanceIds.length; ++i) {
                        instanceId = registeredInstanceIds[i];
                        instance = registeredInstances[instanceId];
                        if (awsInstanceIds.indexOf(instanceId) !== -1) {
                            instances[instanceId] = instance;
                            instances[instanceId].providerVisible = true;
                        }
                        else if (instance.isMaster && !this.isInstanceExpired(instance)) {
                            instances[instanceId] = instance;
                            instances[instanceId].providerVisible = false;
                        }
                        else {
                            // Get a list of non-master instances that we have in our db that AWS
                            // does not know about and delete them
                            idsToDelete.push(INSTANCES_FOLDER + instanceId);
                            idsToDelete.push(PUBLIC_KEYS_FOLDER + instanceId);
                            instancesToRevoke.push(instance);
                        }
                    }

                    // Find instances reported by cloud provider that we do not have
                    for (i = 0; i < awsInstanceIds.length; ++i) {
                        instanceId = awsInstanceIds[i];
                        if (!registeredInstances[instanceId]) {
                            missingInstanceIds.push(instanceId);
                        }
                    }
                    return getInstancesFromEc2(this.ec2, {instanceIds: missingInstanceIds});
                }.bind(this))
                .then(function(response) {

                    response.forEach(function(instance) {
                        instances[instance.InstanceId] = {
                            privateIp: instance.PrivateIpAddress,
                            mgmtIp: instance.PrivateIpAddress,
                            hostname: instance.PrivateDnsName,
                            isMaster: false,
                            providerVisible: true
                        };
                    });

                    logger.debug('Deleting non-masters that are not in AWS', idsToDelete);
                    return deleteObjects(this.s3, this.providerOptions.s3Bucket, idsToDelete, {noWait: true});
                }.bind(this))
                .then(function() {
                    if (instancesToRevoke.length > 0) {
                        logger.debug('Revoking licenses of non-masters that are not known to Azure');
                        return this.revokeLicenses(instancesToRevoke, {bigIp: bigIp});
                    }
                }.bind(this))
                .then(function() {
                    deferred.resolve(instances);
                }.bind(this))
                .catch(function(err) {
                    logger.error('getInstances:', err);
                    deferred.reject(err);
                });
        }
    }.bind(this));

    return deferred.promise;
};

/**
 * Searches for NICs that have a given tag.
 *
 * @param {Object} tag - Tag to search for. Tag is of the format:
 *
 *                 {
 *                     key: optional key
 *                     value: value to search for
 *                 }
 *
 * @returns {Promise} A promise which will be resolved with an array of instances.
 *                    Each instance value should be:
 *
 *                   {
 *                       id: NIC ID,
 *                       ip: {
 *                           public: public IP (or first public IP on the NIC),
 *                           private: private IP (or first private IP on the NIC)
 *                       }
 *                   }
 */
AwsAutoscaleProvider.prototype.getNicsByTag = function(tag) {
    var deferred = q.defer();
    var nics = [];
    var params;
    var nic;

    if (!tag || !tag.key || !tag.value) {
        deferred.reject(new Error('Tag with key and value must be provided'));
        return deferred.promise;
    }

    params = {
        Filters: [
            {
                Name: 'tag:' + tag.key,
                Values: [tag.value]
            }
        ]
    };

    this.ec2.describeNetworkInterfaces(params).promise()
        .then(function(data) {
            if (data.NetworkInterfaces) {
                data.NetworkInterfaces.forEach(function(NetworkInterface) {
                    nic = {
                        id: NetworkInterface.NetworkInterfaceId,
                        ip: {
                            private: NetworkInterface.PrivateIpAddress
                        }
                    };

                    if (NetworkInterface.Association && NetworkInterface.Association.PublicIp) {
                        nic.ip.public = NetworkInterface.Association.PublicIp;
                    }

                    nics.push(nic);
                });
            }
            deferred.resolve(nics);
        }.bind(this))
        .catch(function(err) {
            deferred.reject(err);
        }.bind(this));
    return deferred.promise;
};

/**
 * Searches for VMs that have a given tag.
 *
 * @param {Object} tag - Tag to search for. Tag is of the format:
 *
 *                 {
 *                     key: optional key
 *                     value: value to search for
 *                 }
 *
 * @returns {Promise} A promise which will be resolved with an array of instances.
 *                    Each instance value should be:
 *
 *                   {
 *                       id: instance ID,
 *                       ip: {
 *                           public: public IP (or first public IP on the first NIC),
 *                           private: private IP (or first private IP on the first NIC)
 *                       }
 *                   }
*/
AwsAutoscaleProvider.prototype.getVmsByTag = function(tag) {
    var deferred = q.defer();
    var params;
    var vms = [];
    var vm;

    if (!tag || !tag.key || !tag.value) {
        deferred.reject(new Error('Tag with key and value must be provided'));
        return deferred.promise;
    }

    params = {
        Filters: [
            {
                Name: 'tag:' + tag.key,
                Values: [tag.value]
            }
        ]
    };

    this.ec2.describeInstances(params).promise()
        .then(function(data) {
            if (data.Reservations) {
                data.Reservations.forEach(function(reservation) {

                    if (reservation.Instances) {
                        reservation.Instances.forEach(function(instance) {
                            if (instance.State.Name === 'running') {
                                vm = {
                                    id: instance.InstanceId,
                                    ip: {
                                        private: instance.PrivateIpAddress
                                    }
                                };

                                if (instance.PublicIpAddress) {
                                    vm.ip.public = instance.PublicIpAddress;
                                }

                                vms.push(vm);
                            }
                        });
                    }
                });
            }

            deferred.resolve(vms);
        }.bind(this))
        .catch(function(err) {
            deferred.reject(err);
        }.bind(this));
    return deferred.promise;
};

/**
 * Elects a new master instance from the available instances
 *
 * @param {Object} instances - Dictionary of instances as returned by getInstances.
 *
 * @returns {Promise} A promise which will be resolved with the instance ID of the
 *                    elected master.
 */
AwsAutoscaleProvider.prototype.electMaster = function(instances) {
    var deferred = q.defer();
    var electedMaster = {};
    var ipToNumberList = []; // array of ip addressess converted to numbers for integer comparison
    var instanceIds = [];
    var lowestIpToNumber;
    var index;
    var instanceId;

    // first, validate and build updated list of instances per this node's launch config id
    // in case of autoscale update policy assume that our launch configuration is the correct one
    for (instanceId in instances) {
        if (this.launchConfigMap[instanceId] === this.launchConfigurationName) {
            ipToNumberList.push(ipToNumber(instances[instanceId].privateIp));
            instanceIds.push(instanceId);
        }
    }

    // now elect the master by finding the lowest IP number
    lowestIpToNumber = Math.min.apply(null, ipToNumberList);
    index = ipToNumberList.indexOf(lowestIpToNumber);
    instanceId = instanceIds[index];
    electedMaster = instances[instanceId];

    logger.silly('electMaster: instanceIds:', instanceIds);
    logger.silly('electMaster: lowestIpToNumber:', lowestIpToNumber);
    logger.silly('electMaster: index of lowestIp:', index);
    logger.silly('electMaster: electedMaster:', electedMaster);

    deferred.resolve(instanceId);

    return deferred.promise;
};

/**
 * Gets the public key for an instanceId.
 *
 * @param {String} instanceId - ID of instance to retrieve key for.
 *
 * @returns {Promise} A promise which will be resolved when the operation
 *                    is complete
 */
AutoscaleProvider.prototype.getPublicKey = function(instanceId) {
    return getObject(this.s3, this.providerOptions.s3Bucket, PUBLIC_KEYS_FOLDER + instanceId)
        .then(function(publicKey) {
            return publicKey.toString();
        });
};

 /**
 * Stores the public key for an instanceId.
 *
 * @param {String} instanceId - ID of instance to retrieve key for.
 * @param {String} publicKey - The public key
 *
 * @returns {Promise} A promise which will be resolved when the operation
 *                    is complete
 */
 AutoscaleProvider.prototype.putPublicKey = function(instanceId, publicKey) {
    return putObject(
        this.s3,
        this.providerOptions.s3Bucket,
        PUBLIC_KEYS_FOLDER + instanceId,
        publicKey);
 };

 /**
  * Called to retrieve master instance credentials
  *
  * When joining a cluster we need the username and password for the
  * master instance.
  *
  * Management IP and port are passed in so that credentials can be
  * validated desired.
  *
  * @param {String} mgmtIp - Management IP of master
  * @param {String} port - Managemtn port of master
  *
  * @returns {Promise} A promise which will be resolved with:
  *                    {
  *                        username: <admin_user>,
  *                        password: <admin_password>
  *                    }
  */
 AwsAutoscaleProvider.prototype.getMasterCredentials = function(mgmtIp, mgmtPort) {
     var getAndValidateCredentials = function() {
         var credentials;
         var masterBigIp;
         return getObject(this.s3, this.providerOptions.s3Bucket, CREDENTIALS_KEY)
             .then(function(data) {
                 credentials = JSON.parse(data);
                 logger.debug("Got master credentials from S3. Validating...");
                 masterBigIp = new BigIp({loggerOptions: this.loggerOptions});
                 return masterBigIp.init(mgmtIp, credentials.username, credentials.password, {port: mgmtPort});
             }.bind(this))
             .then(function() {
                 return masterBigIp.ready(cloudUtil.NO_RETRY);
             })
             .then(function() {
                 logger.debug("Validated credentials.");
                 return credentials;
             });
     };

     return cloudUtil.tryUntil(this, cloudUtil.DEFAULT_RETRY, getAndValidateCredentials);
 };

 /**
 * Determines if a given instanceId is a valid master
 *
 * Checks that the launch configuration of the specified master matches
 * our launch configuration.
 *
 * @param {String} instanceId - Instance ID to validate as a valid master.
 *
 * @returns {Promise} A promise which will be resolved with a boolean indicating
 *                    wether or not the given instanceId is a valid master
 */
AwsAutoscaleProvider.prototype.isValidMaster = function(instanceId) {
    if (this.launchConfigMap[instanceId] === this.launchConfigurationName) {
        return q(true);
    }

    return q(false);
};

/**
 * Called when a master has been elected
 *
 * @param {String} masterId - Instance ID that was elected master.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.masterElected = function(instanceId) {
    var promise;

    if (instanceId === this.nodeProperties.instanceId) {
        logger.silly('setting instance protection for ourself');
        promise = setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, true);
    }
    else {
        promise = q();
    }

    return promise
        .then(function() {
            // Find other instance in the db that are marked as master, and mark them as non-master
            return getInstancesFromDb(this.s3, this.providerOptions.s3Bucket);
        }.bind(this))
        .then(function(registeredInstances) {
            var registeredInstanceIds = Object.keys(registeredInstances);
            var promises = [];
            var instance;

            registeredInstanceIds.forEach(function(registeredId) {
                instance = registeredInstances[registeredId];
                if (registeredId !== instanceId && instance.isMaster) {
                    instance.isMaster = false;
                    promises.push(this.putInstance(registeredId, instance));
                }
            }.bind(this));

            // Note: we are not returning the promise here - no need to wait for this to complete
            q.all(promises);
        }.bind(this));
};

/**
 * Indicates that an instance that was master is now invalid
 *
 * @param {String} [instanceId] - Instance ID of instnace that is no longer a valid
 *                                master.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.masterInvalidated = function(instanceId) {
    // we don't care if deleting the instance from S3 is an error - perhaps it was already deleted
    return deleteObjects(this.s3, this.providerOptions.s3Bucket, [INSTANCES_FOLDER + instanceId])
        .finally(function() {
            return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, false);
        });
};

/**
 * Called to get check for and retrieve a stored UCS file
 *
 * Provider implementations can optionally store a UCS to be
 * used to restore a master instance to a last known good state
 *
 * @returns {Promise} A promise which will be resolved with a Buffer containing
 *                    the UCS data if it is present, resolved with undefined if not
 *                    found, or rejected if an error occurs.
 */
AwsAutoscaleProvider.prototype.getStoredUcs = function() {
    var params = {
        Bucket: this.providerOptions.s3Bucket,
        Prefix: BACKUP_FOLDER
    };

    return this.s3.listObjectsV2(params).promise()
        .then(function(data) {
            var newest = {
                LastModified: new Date(1970, 1, 1)
            };

            data.Contents.forEach(function(item) {
                // Ignore the bucket itself
                if (item.Key.endsWith('.ucs')) {
                    if (item.LastModified > newest.LastModified) {
                        newest = item;
                    }
                }
            });

            if (newest.Key) {
                logger.debug('Downloading newest UCS found in S3:', newest.Key);
                return getObject(this.s3, this.providerOptions.s3Bucket, newest.Key);
            }
            else {
                logger.debug('No UCS found in S3');
            }
        }.bind(this));
};

/**
 * Called to store master credentials
 *
 * When joining a cluster we need the username and password for the
 * master instance. This method is called to tell us that we are
 * the master and we should store our credentials if we need to store
 * them for later retrieval in getMasterCredentials.
 *
 * @returns {Promise} A promise which will be resolved when the operation
 *                    is complete
 */
AwsAutoscaleProvider.prototype.putMasterCredentials = function() {

    var deferred = q.defer();
    var passwordPromise;

    passwordPromise = typeof this.clOptions.passwordUrl !== 'undefined' ? cloudUtil.getDataFromUrl(this.clOptions.passwordUrl) : q(this.clOptions.password);
    passwordPromise
        .then(function(password) {
            return putObject(
                this.s3,
                this.providerOptions.s3Bucket,
                CREDENTIALS_KEY,
                JSON.stringify({
                    username: this.clOptions.user,
                    password: password
                }));
        }.bind(this))
        .then(function() {
            logger.debug("Wrote credentials to S3");
            deferred.resolve();
        })
        .catch(function(err) {
            deferred.reject(new Error('Unable to store master credentials: ' + err));
        });

    return deferred.promise;
};

/**
 * Gets info on what this instance thinks the master status is
 *
 * @returns {Promise} A promise which will be resolved with a dictionary of master
 *                    status. Each status value should be:
 *
 *                    {
 *                        "instanceId": masterInstanceId
 *                        "status": AutoscaleProvider.STATUS_*
 *                        "lastUpdate": Date,
 *                        "lastStatusChange": Date
 *                    }
 *
 */
AwsAutoscaleProvider.prototype.getMasterStatus = function() {
    return getStoredInstance(this.s3, this.providerOptions.s3Bucket, this.nodeProperties.instanceId)
        .then(function(response) {
            var instance = response.data;
            var masterStatus;

            masterStatus = instance.masterStatus || {};
            return {
                instanceId: masterStatus.instanceId,
                status: masterStatus.status,
                lastUpdate: masterStatus.lastUpdate,
                lastStatusChange: masterStatus.lastStatusChange
            };
        }.bind(this));
};

/**
 * Saves instance info
 *
 * @param {String} instanceId - ID of instance
 * @param {Object} instance   - Instance information as returned by getInstances.
 *
 * @returns {Promise} A promise which will be resolved with instance info.
 */
AwsAutoscaleProvider.prototype.putInstance = function(instanceId, instance) {
    logger.debug('putInstance: instance:', instance);

    instance.lastUpdate = new Date();

    return putObject(this.s3,
        this.providerOptions.s3Bucket,
        INSTANCES_FOLDER + instanceId,
        JSON.stringify(instance));
};

/**
 * Sends a message to other instances in the scale set
 *
 * @param {String} actionId                 - Action id of message to send
 * @param {Object} [options]                - Optional parameters
 * @param {String} [options.toInstanceId]   - Instance ID that message is for
 * @param {String} [options.fromInstanceId] - Instance ID that message is from
 * @param {Object} [options.data]           - Message specific data
 *
 * @returns {Promise} A promise which will be resolved when the message
 *                    has been sent or rejected if an error occurs
 */
AwsAutoscaleProvider.prototype.sendMessage = function(actionId, options) {
    var params = {
        QueueUrl: this.providerOptions.sqsUrl,
        MessageBody: actionId,
        MessageAttributes: {}
    };

    var key;


    for (key in options) {
        params.MessageAttributes[key] = {
            DataType: 'String',
            StringValue: options[key]
        };
    }

    logger.silly('Sending message', actionId, 'to queue', this.providerOptions.sqsUrl, 'from', params.MessageAttributes.fromInstanceId.StringValue, 'to', params.MessageAttributes.toInstanceId.StringValue);

    return this.sqs.sendMessage(params).promise();
};

/**
 * Gets messages from other instances in the scale set
 *
 * @param {String[]} actions               - Array of actions to get. Other messages will be ignored.
 *                                           Default (empty or undefined) is all actions.
 * @param {Object}  [options]              - Optional parameters
 * @param {String}  [options.toInstanceId] - toInstanceId of messsages we are interested in
 *
 * @returns {Promise} A promise which will be resolved when the messages
 *                    have been received and processed. Promise should be
 *                    resolved with an array of messages of the form
 *
 *                    {
 *                        action: message action id,
 *                        toInstanceId: instanceId,
 *                        fromInstanceId: instanceId,
 *                        data: message specific data used in sendMessage,
 *                        completionHandler: optional completionHandler to call wnen done processing
 *                        {
 *                            this: this arg for callback context,
 *                            callback: function to call,
 *                            data: data to send to function
 *                        }
 *                    }
 */
AwsAutoscaleProvider.prototype.getMessages = function(actions, options) {
    var params = {
        QueueUrl: this.providerOptions.sqsUrl,
        MessageAttributeNames: [
            "All"
        ],
        MaxNumberOfMessages: 10,
        VisibilityTimeout: 7,  // wait for longer than the VisibilityTimeout in case another
        WaitTimeSeconds: 15    // host is looking at this message at the same time
    };
    var deferred = q.defer();
    var messages = [];
    var promises = [];
    var attributes = {};
    var message;
    var attribute;
    var i;

    logger.debug('getting messages from', this.providerOptions.sqsUrl);

    if (actions && actions.length === 0) {
        logger.silly('Not interested in any actions.');
        deferred.resolve(messages);
        return deferred.promise;
    }

    this.sqs.receiveMessage(params).promise()
        .then(function(data) {
            if (data.Messages) {
                logger.silly('Got', data.Messages.length, 'message(s)');
                for (i = 0; i < data.Messages.length; ++i) {

                    message = data.Messages[i];
                    logger.silly('Message', i.toString(), message.Body);

                    if (actions.indexOf(message.Body) === -1) {
                        logger.silly('Not interested in message action', message.Body);
                        continue;
                    }

                    for (attribute in message.MessageAttributes) {
                        attributes[attribute] = message.MessageAttributes[attribute].StringValue;
                    }

                    if (options.toInstanceId) {
                        if (attributes.toInstanceId !== options.toInstanceId) {
                            logger.silly(options.toInstanceId, 'is not interested in messages for', attributes.toInstanceId);
                            continue;
                        }

                    }

                    messages.push(
                        {
                            action: message.Body,
                            toInstanceId: attributes.toInstanceId,
                            fromInstanceId: attributes.fromInstanceId,
                            data: attributes.data
                        }
                    );

                    promises.push(
                        this.sqs.deleteMessage({
                            QueueUrl: this.providerOptions.sqsUrl,
                            ReceiptHandle: message.ReceiptHandle
                        }).promise()
                    );
                }

                logger.silly('Deleting', promises.length, 'message(s)');
                return q.all(promises);
            }
            else {
                logger.silly('no messages');
            }
        }.bind(this))
        .then(function() {
            logger.silly('Interested in', messages.length, 'message(s)');
            deferred.resolve(messages);
        })
        .catch(function(err) {
            logger.warn(err);
            logger.silly('Interested in', messages.length, 'message(s)');
            deferred.resolve(messages);
        });

    return deferred.promise;
};

/**
 * Informs the provider that a sync has completed in case the
 * password needs to be updated
 *
 * When a sync is complete, the user and password will exist on
 * the synced to device.
 *
 * @param {String} fromUser     - User that was synced from
 * @param {String} fromPassword - Password that was synced from
 *
 * @returns {Promise} A promise which will be resolved when the messages
 *                    have been received and processed
 */
AwsAutoscaleProvider.prototype.syncComplete = function(fromUser, fromPassword) {
    var deferred = q.defer();
    var file;

    // update the bigIp password
    logger.debug('Updating local password');
    bigIp.password = fromPassword;

    logger.debug('Updating local password file');
    if (this.clOptions.passwordUrl) {
        // strip off 'file://'
        file = this.clOptions.passwordUrl.substring(7);
        fs.writeFile(file, fromPassword, {mode: 0x400}, function(err) {
            if (err) {
                logger.warn('Unable to update password URL', this.clOptions.passwordUrl);
                deferred.reject();
                return;
            }
            deferred.resolve();
        });
    }
    else {
        deferred.resolve();
    }

    return deferred.promise;
};

var getTemporaryCredentials = function(providerOptions, sessionName) {
    var params = {
        RoleArn: providerOptions.roleArn.trim(),
        ExternalId: providerOptions.externalId.trim(),
        RoleSessionName: sessionName
    };
    Aws.config.credentials = new Aws.TemporaryCredentials(params);
    return q();
};

/**
 * Reads the iid doc (generated by AWS) and returns data in a map
 */
var getIidDoc = function() {
    var deferred = q.defer();
    var filename = '/shared/vadc/aws/iid-document';

    fs.readFile(filename, function (err, data) {
        if (err) {
            deferred.reject(err);
        }
        else {
            deferred.resolve(JSON.parse(data.toString()));
        }
    });

    return deferred.promise;
};

/**
 * Reads info about this instance from AWS
 */
 var getAutoScalingInstanceInfo = function(autoscaling, instanceId) {
    return autoscaling.describeAutoScalingInstances({InstanceIds: [instanceId]}).promise()
        .then(function(data) {
            return data.AutoScalingInstances[0];
        });
 };

/**
 * Gets our view of the current instances
 *
 * @param {Object} s3 - Aws.s3 instance
 * @param {String} s3Bucket - Name of S3 bucket storing our database
 *
 * @returns {Object} Object containing a dictionary of S3 objects keyed by Instance IDs
 */
var getInstancesFromDb = function(s3, s3Bucket) {
    var deferred = q.defer();
    var instances = {};
    var params = {
        Bucket: s3Bucket,
        Prefix: INSTANCES_FOLDER
    };
    var getPromises = [];
    var prefixLength = params.Prefix.length;

    s3.listObjectsV2(params).promise()
        .then(function(data) {
            logger.silly('getInstancesFromDb: S3 bucket size:', data.Contents.length);

            data.Contents.forEach(function (element) {
                var instanceId = element.Key.substr(prefixLength);
                if (instanceId) {
                    getPromises.push(getStoredInstance(s3, s3Bucket, element.Key));
                }
            });

            q.all(getPromises)
                .then(function(responses) {
                    var i;

                    logger.debug('getInstancesFromDb: instances:', responses);

                    for (i = 0; i < responses.length; ++i) {
                        if (responses[i]) {
                            instances[responses[i].instanceId] = responses[i].data;
                        }
                    }

                    deferred.resolve(instances);
                });
        })
        .catch(function(err) {
            deferred.reject(err);
        });

    return deferred.promise;
};

/**
 * Gets EC2 instances
 *
 * @param {Object} ec2 - AWS.ec2 instances
 * @param {Object} [options] - optional paramaters
 * @param {String[]} [options.instanceIds] - Array of instance IDs to retrieve. Default is to retrieve all.
 * @param {Object[]} [options.tags] - Array of tags to filter by. Tag is {key: key, value: value}.
 *
 * @returns {Promise} Promise resolved with the result or rejected if an error occurs.
 */
var getInstancesFromEc2 = function(ec2, options) {
    var deferred = q.defer();
    var params = {};
    var filters = [];
    var ec2Instances = [];

    if (options.instanceIds && options.instanceIds.length > 0) {
        params.InstanceIds = options.instanceIds;
    }

    if (options.tags && options.tags.length > 0) {
        options.tags.forEach(function(tag) {
            filters.push({
                Name: 'tag:' + tag.key,
                Value: tag.value
            });
        });

        params.Filters = filters;
    }

    if (params.InstanceIds || params.Filters) {
        ec2.describeInstances(params).promise()
            .then(function(data) {
                if (data.Reservations) {
                    data.Reservations.forEach(function(reservation) {
                        if (reservation.Instances) {
                            reservation.Instances.forEach(function(instance) {
                                ec2Instances.push(instance);
                            });
                        }
                    });
                }
                deferred.resolve(ec2Instances);
            })
            .catch(function(err) {
                deferred.reject(err);
            });
    }
    else {
        deferred.resolve(ec2Instances);
    }

    return deferred.promise;
};

var getStoredInstance = function(s3, s3Bucket, key) {
    var deferred = q.defer();
    var prefixLength = INSTANCES_FOLDER.length;

    if (!key.startsWith(INSTANCES_FOLDER)) {
        key = INSTANCES_FOLDER + key;
    }

    logger.silly('Getting stored instance', key);

    getObject(s3, s3Bucket, key)
        .then(function(data) {
            var instanceId = key.substr(prefixLength);
            var parsed;

            try {
                parsed = JSON.parse(data);
                deferred.resolve({instanceId: instanceId, data: parsed});
            }
            catch (err) {
                deferred.reject(new Error('getObject: ' + err));
            }
        })
        .catch(function() {
            logger.silly('Error caught getting stored instance.');
            deferred.resolve();
        });
    return deferred.promise;
};

/**
 * Generic S3 listObjectsV2
 *
 * @param {Aws.s3}  s3       - Aws.S3 instance
 * @param {String}  s3Bucket - Aws S3 bucket indentifier
 * @param {String}  [prefix] - Prefix for listObjectsV2
 *
 * @returns {Promise} Promise which will be resolved with the data
 */
var listObjects = function(s3, s3Bucket, prefix) {
    var params = {
        Bucket: s3Bucket,
    };

    if (prefix) {
        params.Prefix = prefix;
    }

    var doList = function() {
        var deferred = q.defer();

        // create the backup folder if it is not there
        s3.listObjectsV2(params).promise()
            .then(function(data) {
                deferred.resolve(data);
            })
            .catch(function(err) {
                deferred.reject(err);
            });
        return deferred.promise;
    };

    return cloudUtil.tryUntil(this, cloudUtil.MEDIUM_RETRY, doList);
};

/**
 * Generic S3 getObject
 *
 * @param {Aws.s3}  s3       - Aws.S3 instance
 * @param {String}  s3Bucket - Aws S3 bucket indentifier
 * @param {String}  key      - key for data
 *
 * @returns {Promise} Promise which will be resolved with the data
 */
var getObject = function(s3, s3Bucket, key) {
    var params = {
        Bucket: s3Bucket,
        Key: key
    };

    logger.silly('getting object', params);

    var doGet = function() {
        var deferred = q.defer();

        s3.getObject(params).promise()
            .then(function(data) {
                deferred.resolve(data.Body);
            })
            .catch(function(err) {
                deferred.reject(err);
            });
        return deferred.promise;
    };

    // Even with the built-in S3 retry options, we still see failures
    // occasionally so do our own retry
    return cloudUtil.tryUntil(this, cloudUtil.MEDIUM_RETRY, doGet);
};

/**
 * Generic S3 putObject
 *
 * @param {Aws.s3}        s3       - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket - Aws S3 bucket indentifier
 * @param {String}        key      - key for data
 * @param {String}        [data]   - String representation of data
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
var putObject = function(s3, s3Bucket, key, data) {
    var params = {
        Bucket: s3Bucket,
        Key: key
    };

    if (data) {
        params.Body = data;
    }

    var doPut = function() {
        var deferred = q.defer();

        s3.putObject(params).promise()
            .then(function(data) {
                deferred.resolve(data);
            })
            .catch(function(err) {
                deferred.reject(err);
            });

        return deferred.promise;
    };

    return cloudUtil.tryUntil(this, cloudUtil.SHORT_RETRY, doPut);
};

/**
 * Generic S3 deleteObject
 *
 * @param {Aws.s3}        s3               - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket         - Aws S3 bucket indentifier
 * @param {String[]}      keys             - Array of keys to delete
 * @param {Object}        [options]        - Optional parameters
 * @param {Boolean}       [options.noWait] - Whether or not to wait for completion before returning. Default is to wait.
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
var deleteObjects = function(s3, s3Bucket, keys, options) {
    var keyParams = [];
    var params;

    options = options || {};

    if (keys.length > 0) {
        keys.forEach(function(key) {
            keyParams.push({Key: key});
        });

        params = {
            Bucket: s3Bucket,
            Delete: {
                Objects: keyParams
            }
        };

        var doDelete = function() {
            var deferred = q.defer();

            s3.deleteObjects(params).promise()
                .then(function(data) {
                    deferred.resolve(data);
                })
                .catch(function(err) {
                    deferred.reject(err);
                });
            return deferred.promise;
        };

        if (options.noWait) {
            doDelete();
            return q();
        }
        else {
            return cloudUtil.tryUntil(this, cloudUtil.SHORT_RETRY, doDelete);
        }
    }
    else {
        return q();
    }
};

var setInstanceProtection = function(autoscaling, instanceId, autoscaleGroupId, status) {
    var deferred = q.defer();

    var params = {
        AutoScalingGroupName: autoscaleGroupId,
        InstanceIds: [ instanceId ],
        ProtectedFromScaleIn: status
    };

    autoscaling.setInstanceProtection(params, function(err, data) {
        if (err) {
            deferred.reject(err);
        } else {
            deferred.resolve(data);
        }
    });

    return deferred.promise;
};

var ipToNumber = function(ip) {
    var d = ip.split('.');
    var n = d[0] * Math.pow(256, 3);
    n += d[1] * Math.pow(256, 2);
    n += d[2] * 256;
    n += d[3] * 1;
    return n;
};

module.exports = AwsAutoscaleProvider;
