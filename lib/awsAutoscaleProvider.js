/**
 * Copyright 2016-2018 F5 Networks, Inc.
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

const fs = require('fs');
const util = require('util');
const path = require('path');
const crypto = require('crypto');

const Aws = require('aws-sdk');
const q = require('q');

const CREDENTIALS_KEY = 'credentials/master';
const INSTANCES_FOLDER = 'instances/';
const BACKUP_FOLDER = 'backup/';
const PUBLIC_KEYS_FOLDER = 'public_keys/';

const STACK_ID_TAG = 'aws:cloudformation:stack-id';

const AutoscaleInstance = require('@f5devcentral/f5-cloud-libs').autoscaleInstance;
const AutoscaleProvider = require('@f5devcentral/f5-cloud-libs').autoscaleProvider;
const BigIp = require('@f5devcentral/f5-cloud-libs').bigIp;
const Logger = require('@f5devcentral/f5-cloud-libs').logger;
const cloudUtil = require('@f5devcentral/f5-cloud-libs').util;
const cryptoUtil = require('@f5devcentral/f5-cloud-libs').cryptoUtil;
const localCryptoUtil = require('@f5devcentral/f5-cloud-libs').localCryptoUtil;
const KEYS = require('@f5devcentral/f5-cloud-libs').sharedConstants.KEYS;

let bigIp;
let logger;

const AWS_RETRY_OPTIONS = {
    httpOptions: { timeout: 120000 },
    maxRetries: 20,
    retryDelayOptions: { base: 300 }
};

util.inherits(AwsAutoscaleProvider, AutoscaleProvider);

/**
  * Constructor.
  * @class
  *
  * @param {Ojbect} [options]               - Options for the instance.
  * @param {Object} [options.clOptions]     - Command line options if called from a script.
  * @param {Object} [options.logger]        - Logger to use. Or, pass loggerOptions to get your own logger.
  * @param {Object} [options.loggerOptions] - Options for the logger.
  *                                           See {@link module:logger.getLogger} for details.
  */
function AwsAutoscaleProvider(options) {
    AwsAutoscaleProvider.super_.call(this, options);

    this.features[AutoscaleProvider.FEATURE_MESSAGING] = true;
    this.features[AutoscaleProvider.FEATURE_ENCRYPTION] = true;

    const loggerOptions = options ? options.loggerOptions : undefined;

    logger = options ? options.logger : undefined;

    if (logger) {
        this.logger = logger;
        cloudUtil.setLogger(logger);
        cryptoUtil.setLogger(logger);
    } else if (loggerOptions) {
        loggerOptions.module = module;
        logger = Logger.getLogger(loggerOptions);
        cloudUtil.setLoggerOptions(loggerOptions);
        cryptoUtil.setLoggerOptions(loggerOptions);
        this.logger = logger;
    } else {
        // use super's logger
        logger = this.logger;
        cloudUtil.setLogger(logger);
        cryptoUtil.setLogger(logger);
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
 * @param {Boolean} [options.autoscale]             - Whether or not this instance will
 *                                                    be used for autoscaling.
 *
 * @returns {Promise} A promise which will be resolved when init is complete.
 */
AwsAutoscaleProvider.prototype.init = function init(providerOptions, options) {
    this.providerOptions = providerOptions || {};
    this.initOptions = options || {};

    if (this.initOptions.autoscale) {
        if (!this.providerOptions.s3Bucket) {
            return q.reject(new Error('ProviderOptions.s3Bucket required when used for autoscaling'));
        }

        if (!this.providerOptions.sqsUrl) {
            return q.reject(new Error('ProviderOptions.sqsUrl required when used for autoscaling'));
        }
    }

    this.providerOptions.mgmtPort = this.providerOptions.mgmtPort || '443';

    this.nodeProperties = {};
    this.instancesToRevoke = [];
    this.instanceIdToLaunchConfigMap = {};
    this.instanceIdToAutoscaleGroupMap = {};
    this.stackIdToInstanceMap = {};
    this.autoscaleGroupToLaunchConfigMap = {};

    return getIidDoc()
        .then((response) => {
            if (response) {
                this.nodeProperties.mgmtIp = response.privateIp;
                this.nodeProperties.privateIp = response.privateIp;
                this.nodeProperties.instanceId = response.instanceId;
                this.nodeProperties.region = response.region;
            }

            if (!this.providerOptions.region && !this.nodeProperties.region) {
                const message = 'No region found in provider options or iid doc';
                return q.reject(new Error(message));
            }

            Aws.config.update({ region: this.providerOptions.region || this.nodeProperties.region });
            Aws.config.update(AWS_RETRY_OPTIONS);

            if (this.providerOptions.secretId && this.providerOptions.accessKeyId) {
                return getSecret(this.providerOptions.secretId, this.providerOptions.accessKeyId)
                    .then((secretAccessKey) => {
                        Aws.config.credentials =
                            new Aws.Credentials(this.providerOptions.accessKeyId, secretAccessKey);
                        return q();
                    })
                    .catch((err) => {
                        const message = (`Error retrieving secret access key: ${err}`);
                        this.logger.info(message);
                        return q.reject(new Error(message));
                    });
            }

            Aws.config.credentials = new Aws.EC2MetadataCredentials(AWS_RETRY_OPTIONS);
            return q();
        })
        .then(() => {
            if (this.providerOptions.roleArn
                && !(this.providerOptions.roleArn === "''" || this.providerOptions.roleArn === '""')) {
                return getTemporaryCredentials(this.providerOptions, this.nodeProperties.instanceId);
            }
            return q();
        })
        .then(() => {
            this.s3 = new Aws.S3();
            this.ec2 = new Aws.EC2();
            this.autoscaling = new Aws.AutoScaling();
            this.sqs = new Aws.SQS({
                sslEnabled: true
            });

            if (this.initOptions.autoscale) {
                return getAutoScalingInstanceInfo(this.autoscaling, this.nodeProperties.instanceId);
            }
            return q();
        })
        .then((response) => {
            if (this.initOptions.autoscale) {
                this.nodeProperties.autoscaleGroupId = response.AutoScalingGroupName;
            }

            if (this.initOptions.autoscale) {
                return getAutoscalingGroups(this.autoscaling);
            }

            return q();
        })
        .then((autoscalingGroups) => {
            if (autoscalingGroups) {
                const populateMaps = function (autoscaleGroup) {
                    const instances = autoscaleGroup.Instances;

                    for (let i = 0; i < instances.length; ++i) {
                        const instanceId = instances[i].InstanceId;
                        const stackId = getStackIdFromAutoscaleGroup(autoscaleGroup);

                        this.instanceIdToAutoscaleGroupMap[instanceId] = autoscaleGroup.AutoScalingGroupName;
                        this.instanceIdToLaunchConfigMap[instanceId] = instances[i].LaunchConfigurationName;

                        if (!this.stackIdToInstanceMap[stackId]) {
                            this.stackIdToInstanceMap[stackId] = [];
                        }
                        this.stackIdToInstanceMap[stackId].push(instances[i]);
                    }
                };

                autoscalingGroups.forEach((autoscaleGroup) => {
                    this.autoscaleGroupToLaunchConfigMap[autoscaleGroup.AutoScalingGroupName] =
                        autoscaleGroup.LaunchConfigurationName;
                    populateMaps.call(this, autoscaleGroup);
                });
            }

            if (this.providerOptions.s3Bucket) {
                const deferred = q.defer();

                // create the backup folder if it is not there
                listObjects(this.s3, this.providerOptions.s3Bucket, BACKUP_FOLDER)
                    .then((data) => {
                        if (data.KeyCount !== 0) {
                            logger.silly('Backup folder already exists');
                            deferred.resolve();
                        } else {
                            logger.debug('Creating backup folder');
                            putObject(this.s3, this.providerOptions.s3Bucket, BACKUP_FOLDER)
                                .then(() => {
                                    logger.silly('Backup folder created');
                                    deferred.resolve();
                                })
                                .catch((err) => {
                                    logger.warn('Error creating backup folder', err);
                                    deferred.reject(err);
                                });
                        }
                    })
                    .catch((err) => {
                        logger.warn('Error checking for backup folder', err);
                        deferred.reject(err);
                    });

                return deferred.promise;
            }
            return q();
        });
};

/**
 * BIG-IP is now ready and providers can run BIG-IP functions
 * if necessary
 *
 * @returns {Promise} A promise which will be resolved when init is complete.
 */
AwsAutoscaleProvider.prototype.bigIpReady = function bigIpReady() {
    if (this.clOptions.user && (this.clOptions.password || this.clOptions.passwordUrl)) {
        bigIp = new BigIp({ loggerOptions: this.loggerOptions });
        return bigIp.init(
            'localhost',
            this.clOptions.user,
            this.clOptions.password || this.clOptions.passwordUrl,
            {
                port: parseInt(this.providerOptions.mgmtPort, 10),
                passwordIsUrl: typeof this.clOptions.passwordUrl !== 'undefined',
                passwordEncrypted: this.clOptions.passwordEncrypted
            }
        )
            .then(() => {
                if (this.initOptions.autoscale) {
                    // We also need to write the autoscaleGroupId to BIG-IP to signal it to
                    // collect metrics for CloudWatch
                    return bigIp.modify(
                        '/tm/sys/autoscale-group',
                        {
                            autoscaleGroupId: this.nodeProperties.autoscaleGroupId
                        }
                    );
                }
                return q();
            })
            .then(() => {
                if (this.instancesToRevoke.length > 0) {
                    logger.debug('Revoking licenses of non-masters that are not known to AWS');
                    return this.revokeLicenses(this.instancesToRevoke, { bigIp });
                }
                return q();
            });
    }
    return q();
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
AwsAutoscaleProvider.prototype.getDataFromUri = function getDataFromUri(uri) {
    if (!uri.startsWith('arn:aws:s3:::')) {
        return q.reject(new Error('Invalid URI. URI should be an S3 arn.'));
    }

    // ARN format is arn:aws:s3:::bucket_name/key_name
    let parts = uri.split(':::');

    // Get the bucket/key
    parts = parts[1].split(/\/(.+)/);

    // length === 3 because splitting on just the first match leaves an empty string at the end
    if (parts.length !== 3) {
        return q.reject(new Error('Invalid ARN. Format should be arn:aws:s3:::bucket_name/key_name'));
    }

    const bucket = parts[0];
    const key = parts[1];

    return getObject(this.s3, bucket, key)
        .then((data) => {
            return data.toString();
        })
        .catch((err) => {
            return q.reject(err);
        });
};

/**
 * Gets the instance ID of this instance
 *
 * @returns {Promise} A promise which will be resolved with the instance ID of this instance
 *                    or rejected if an error occurs;
 */
AwsAutoscaleProvider.prototype.getInstanceId = function getInstanceId() {
    return q(this.nodeProperties.instanceId);
};

/**
 * Gets info for each instance
 *
 * Reports instances which are marked as master and/or visible to the cloud provider
 *
 * @param {Object} [options]             - Optional parameters
 * @param {String} [options.externalTag] - Also look for instances with this tag
 *                                         (outside of the autoscale group/set)
 *
 * @returns {Promise} A promise which will be resolved with a dictionary of instances
 *                    keyed by instance ID. Each instance value should be:
 *
 *                   {
 *                       isMaster: <Boolean>,
 *                       hostname: <String>,
 *                       mgmtIp: <String>,
 *                       privateIp: <String>,
 *                       publicIp: <String>,
 *                       providerVisible: <Boolean> (does the cloud provider know about this instance),
 *                       external: <Boolean> (true if this instance is external to the autoscale group/set)
 *                   }
 */
AwsAutoscaleProvider.prototype.getInstances = function getInstances(options) {
    const deferred = q.defer();
    const instances = {};
    const awsInstanceIds = [];
    const missingInstanceIds = [];
    const idsToDelete = [];
    const externalInstanceIds = [];

    const externalTag = options ? options.externalTag : undefined;

    const BAD_STATES = ['Terminating', 'Terminating:Wait', 'Terminating:Proceed', 'Terminated'];

    let instanceId;

    const filterInstances = function (awsInstances) {
        return awsInstances.filter((instance) => {
            return BAD_STATES.indexOf(instance.LifecycleState) === -1;
        });
    };

    // First, get our stack ID and find all the instances in it
    getAutoscalingGroups(this.autoscaling, this.nodeProperties.autoscaleGroupId)
        .then((data) => {
            const autoscalingGroup = data[0];

            this.stackId = getStackIdFromAutoscaleGroup(autoscalingGroup);

            logger.silly(`getInstances: Got ${autoscalingGroup.Instances.length} in autoscale group`);

            const instancesToConsider = filterInstances(this.stackIdToInstanceMap[this.stackId]);
            logger.silly(`getInstances: Considering ${instancesToConsider.length} instances`);

            instancesToConsider.forEach((instance) => {
                instanceId = instance.InstanceId;
                logger.silly('getInstances: adding instance:', instanceId);
                awsInstanceIds.push(instanceId);
                this.instanceIdToLaunchConfigMap[instanceId] = instance.LaunchConfigurationName;
            });

            if (externalTag) {
                return this.getVmsByTag(externalTag, { includePending: true });
            }

            return q();
        })
        .then((externalInstances) => {
            let externals;

            logger.silly('getInstances: external instances', externalInstances);

            if (externalInstances) {
                externals = externalInstances.slice();
            } else {
                externals = [];
            }

            externals.forEach((instance) => {
                if (awsInstanceIds.indexOf(instance.id) === -1) {
                    awsInstanceIds.push(instance.id);
                }
                if (externalInstanceIds.indexOf(instance.id) === -1) {
                    externalInstanceIds.push(instance.id);
                }
            });

            // Now get info from our database
            return getInstancesFromDb(this.s3, this.providerOptions.s3Bucket);
        })
        .then((registeredInstances) => {
            const registeredInstanceIds = Object.keys(registeredInstances);
            let instance;

            for (let i = 0; i < registeredInstanceIds.length; i++) {
                instanceId = registeredInstanceIds[i];
                instance = registeredInstances[instanceId];
                if (awsInstanceIds.indexOf(instanceId) !== -1) {
                    instances[instanceId] = instance;
                    instances[instanceId].providerVisible = true;
                } else if (instance.isMaster && !this.isInstanceExpired(instance)) {
                    instances[instanceId] = instance;
                    instances[instanceId].providerVisible = false;
                } else {
                    // Get a list of non-master instances that we have in our db that AWS
                    // does not know about and delete them
                    idsToDelete.push(INSTANCES_FOLDER + instanceId);
                    idsToDelete.push(PUBLIC_KEYS_FOLDER + instanceId);
                    this.instancesToRevoke.push(instance);
                }
            }

            // Find instances reported by cloud provider that we do not have
            for (let i = 0; i < awsInstanceIds.length; i++) {
                instanceId = awsInstanceIds[i];
                if (!registeredInstances[instanceId]) {
                    missingInstanceIds.push(instanceId);
                }
            }
            return getInstancesFromEc2(this.ec2, { instanceIds: missingInstanceIds });
        })
        .then((response) => {
            response.forEach((instance) => {
                const autoscaleInstance = new AutoscaleInstance()
                    .setPrivateIp(instance.PrivateIpAddress)
                    .setPublicIp(instance.PublicIpAddress)
                    .setMgmtIp(instance.PrivateIpAddress)
                    .setHostname(instance.PrivateDnsName);
                instances[instance.InstanceId] = autoscaleInstance;
            });

            logger.debug('Deleting non-masters that are not in AWS', idsToDelete);
            return deleteObjects(this.s3, this.providerOptions.s3Bucket, idsToDelete, { noWait: true });
        })
        .then(() => {
            externalInstanceIds.forEach((externalInstanceId) => {
                if (instances[externalInstanceId]) {
                    instances[externalInstanceId].external = true;
                }
            });
            deferred.resolve(instances);
        })
        .catch((err) => {
            logger.error('getInstances:', err);
            deferred.reject(err);
        });

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
AwsAutoscaleProvider.prototype.getNicsByTag = function getNicsByTag(tag) {
    const deferred = q.defer();
    const nics = [];

    if (!tag || !tag.key || !tag.value) {
        deferred.reject(new Error('Tag with key and value must be provided'));
        return deferred.promise;
    }

    const params = {
        Filters: [
            {
                Name: `tag:${tag.key}`,
                Values: [tag.value]
            }
        ]
    };

    this.ec2.describeNetworkInterfaces(params).promise()
        .then((data) => {
            if (data.NetworkInterfaces) {
                data.NetworkInterfaces.forEach((NetworkInterface) => {
                    const nic = {
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
        })
        .catch((err) => {
            deferred.reject(err);
        });
    return deferred.promise;
};

/**
 * Searches for VMs that have a given tag.
 *
 * @param {Object}  tag                     - Tag to search for. Tag is of the format:
 *
 *                  {
 *                      key: optional key
 *                      value: value to search for
 *                  }
 * @param {Object}  [options]                - Optional parameters.
 * @param {Boolean} [options.includePending] - Include pending instances.
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
AwsAutoscaleProvider.prototype.getVmsByTag = function getVmsByTag(tag, options) {
    const deferred = q.defer();
    const vms = [];

    const includePending = options ? options.includePending : false;

    if (!tag || !tag.key || !tag.value) {
        deferred.reject(new Error('Tag with key and value must be provided'));
        return deferred.promise;
    }

    const params = {
        Filters: [
            {
                Name: `tag:${tag.key}`,
                Values: [tag.value]
            }
        ]
    };

    const validInstanceStates = ['running'];
    if (includePending) {
        validInstanceStates.push('pending');
    }

    this.ec2.describeInstances(params).promise()
        .then((data) => {
            if (data.Reservations) {
                data.Reservations.forEach((reservation) => {
                    if (reservation.Instances) {
                        reservation.Instances.forEach((instance) => {
                            if (validInstanceStates.indexOf(instance.State.Name) !== -1) {
                                const vm = {
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
        })
        .catch((err) => {
            deferred.reject(err);
        });
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
AwsAutoscaleProvider.prototype.electMaster = function electMaster(instances) {
    let lowestGlobalIp = Number.MAX_SAFE_INTEGER;
    let lowestExternalIp = Number.MAX_SAFE_INTEGER;

    let currentIpToNumber;
    let masterId;
    let externalMasterId;

    const canInstanceBeElected = function (instance, instanceId) {
        if (instance.versionOk && instance.providerVisible) {
            // Make sure the launch config name of the instance matches
            // the launch config name of the autoscale group it is in
            const instanceLaunchConfigName = this.instanceIdToLaunchConfigMap[instanceId];
            const instanceAutoscaleGroup = this.instanceIdToAutoscaleGroupMap[instanceId];
            const autoscaleGroupLaunchConfigName =
                this.autoscaleGroupToLaunchConfigMap[instanceAutoscaleGroup];

            if (instanceLaunchConfigName === autoscaleGroupLaunchConfigName) {
                return true;
            }
        }
        return false;
    };

    Object.keys(instances).forEach((instanceId) => {
        const instance = instances[instanceId];
        if (canInstanceBeElected.call(this, instance, instanceId)) {
            currentIpToNumber = cloudUtil.ipToNumber(instance.privateIp);
            if (currentIpToNumber < lowestGlobalIp) {
                lowestGlobalIp = currentIpToNumber;
                masterId = instanceId;
            }
            if (instance.external) {
                if (currentIpToNumber < lowestExternalIp) {
                    lowestExternalIp = currentIpToNumber;
                    externalMasterId = instanceId;
                }
            }
        }
    });

    // prefer external instances (for example, BYOL instances)
    if (externalMasterId) {
        logger.silly('electMaster: using external master');
        masterId = externalMasterId;
    }
    logger.silly('electMaster: electedMaster:', instances[masterId]);

    return q(masterId);
};

/**
 * Gets the public key for an instanceId.
 *
 * @param {String} instanceId - ID of instance to retrieve key for.
 *
 * @returns {Promise} A promise which will be resolved when the operation
 *                    is complete
 */
AutoscaleProvider.prototype.getPublicKey = function getPublicKey(instanceId) {
    return getObject(this.s3, this.providerOptions.s3Bucket, PUBLIC_KEYS_FOLDER + instanceId)
        .then((publicKey) => {
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
AutoscaleProvider.prototype.putPublicKey = function putPublicKey(instanceId, publicKey) {
    return putObject(
        this.s3,
        this.providerOptions.s3Bucket,
        PUBLIC_KEYS_FOLDER + instanceId,
        publicKey
    );
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
AwsAutoscaleProvider.prototype.getMasterCredentials = function getMasterCredentials(mgmtIp, mgmtPort) {
    const getAndValidateCredentials = function () {
        let credentials;
        let masterBigIp;
        return getObject(this.s3, this.providerOptions.s3Bucket, CREDENTIALS_KEY)
            .then((data) => {
                credentials = JSON.parse(data);
                logger.debug('Got master credentials from S3. Validating...');
                masterBigIp = new BigIp({ loggerOptions: this.loggerOptions });
                return masterBigIp.init(
                    mgmtIp,
                    credentials.username,
                    credentials.password,
                    {
                        port: mgmtPort
                    }
                );
            })
            .then(() => {
                return masterBigIp.ready(cloudUtil.NO_RETRY);
            })
            .then(() => {
                logger.debug('Validated credentials.');
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
AwsAutoscaleProvider.prototype.isValidMaster = function isValidMaster() {
    return q(true);
};

/**
 * Called when a master has been elected
 *
 * @param {String} masterId - Instance ID that was elected master.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.masterElected = function masterElected(instanceId) {
    let promise;

    if (instanceId === this.nodeProperties.instanceId) {
        logger.silly('setting instance protection for ourself');
        promise = setInstanceProtection(
            this.autoscaling,
            instanceId,
            this.nodeProperties.autoscaleGroupId,
            true
        );
    } else {
        promise = q();
    }

    return promise
        .then(() => {
            // Find other instance in the db that are marked as master, and mark them as non-master
            return getInstancesFromDb(this.s3, this.providerOptions.s3Bucket);
        })
        .then((registeredInstances) => {
            const registeredInstanceIds = Object.keys(registeredInstances);
            const promises = [];

            registeredInstanceIds.forEach((registeredId) => {
                const instance = registeredInstances[registeredId];
                if (registeredId !== instanceId && instance.isMaster) {
                    instance.isMaster = false;
                    promises.push(this.putInstance(registeredId, instance));
                }
            });

            // Note: we are not returning the promise here - no need to wait for this to complete
            q.all(promises);
        });
};

/**
 * Indicates that an instance that was master is now invalid
 *
 * @param {String} [instanceId] - Instance ID of instnace that is no longer a valid
 *                                master.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.masterInvalidated = function masterInvalidated(instanceId) {
    // we don't care if deleting the instance from S3 is an error - perhaps it was already deleted
    return deleteObjects(this.s3, this.providerOptions.s3Bucket, [INSTANCES_FOLDER + instanceId])
        .finally(() => {
            return setInstanceProtection(
                this.autoscaling,
                instanceId,
                this.nodeProperties.autoscaleGroupId,
                false
            );
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
AwsAutoscaleProvider.prototype.getStoredUcs = function getStoredUcs() {
    const params = {
        Bucket: this.providerOptions.s3Bucket,
        Prefix: BACKUP_FOLDER
    };

    return this.s3.listObjectsV2(params).promise()
        .then((data) => {
            let newest = {
                LastModified: new Date(1970, 1, 1)
            };

            data.Contents.forEach((item) => {
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
            logger.debug('No UCS found in S3');
            return q();
        });
};

/**
 * Stores a UCS file in cloud storage
 *
 * @param {String} file      - Full path to file to store.
 * @param {Number} maxCopies - Number of files to store. Oldest files over
 *                             this number should be deleted.
 * @param {String} prefix    - The common prefix for autosaved UCS files
 *
 * @returns {Promise} A promise which is resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.storeUcs = function storeUcs(file, maxCopies, prefix) {
    const key = `${BACKUP_FOLDER}${path.basename(file)}`;
    return putObject(this.s3, this.providerOptions.s3Bucket, key, fs.createReadStream(file))
        .then(() => {
            return deleteOldestObjects(
                this.s3,
                this.providerOptions.s3Bucket,
                BACKUP_FOLDER,
                maxCopies,
                prefix
            );
        })
        .catch((err) => {
            return q.reject(new Error(`storeUcs: ${err}`));
        });
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
AwsAutoscaleProvider.prototype.putMasterCredentials = function putMasterCredentials() {
    const deferred = q.defer();

    bigIp.getPassword()
        .then((password) => {
            return putObject(
                this.s3,
                this.providerOptions.s3Bucket,
                CREDENTIALS_KEY,
                JSON.stringify({
                    password,
                    username: this.clOptions.user
                })
            );
        })
        .then(() => {
            logger.debug('Wrote credentials to S3');
            deferred.resolve();
        })
        .catch((err) => {
            deferred.reject(new Error(`Unable to store master credentials: ${err}`));
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
 *                        'instanceId": masterInstanceId
 *                        "status": AutoscaleProvider.STATUS_*
 *                        "lastUpdate": Date,
 *                        "lastStatusChange": Date
 *                    }
 *
 */
AwsAutoscaleProvider.prototype.getMasterStatus = function getMasterStatus() {
    return getStoredInstance(this.s3, this.providerOptions.s3Bucket, this.nodeProperties.instanceId)
        .then((response) => {
            const instance = response.data;
            const masterStatus = instance.masterStatus || {};

            return {
                instanceId: masterStatus.instanceId,
                status: masterStatus.status,
                lastUpdate: masterStatus.lastUpdate,
                lastStatusChange: masterStatus.lastStatusChange
            };
        });
};

/**
 * Saves instance info
 *
 * @param {String} instanceId - ID of instance
 * @param {Object} instance   - Instance information as returned by getInstances.
 *
 * @returns {Promise} A promise which will be resolved with instance info.
 */
AwsAutoscaleProvider.prototype.putInstance = function putInstance(instanceId, instance) {
    logger.debug('putInstance: instance:', instance);

    const instanceToUpdate = instance;
    instanceToUpdate.lastUpdate = new Date();

    return putObject(this.s3,
        this.providerOptions.s3Bucket,
        INSTANCES_FOLDER + instanceId,
        JSON.stringify(instanceToUpdate));
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
AwsAutoscaleProvider.prototype.sendMessage = function sendMessage(actionId, options) {
    const params = {
        QueueUrl: this.providerOptions.sqsUrl,
        MessageBody: actionId,
        MessageAttributes: {}
    };

    Object.keys(options).forEach((key) => {
        params.MessageAttributes[key] = {
            DataType: 'String',
            StringValue: options[key]
        };
    });

    logger.silly(
        'Sending message',
        actionId,
        'to queue',
        this.providerOptions.sqsUrl,
        'from',
        params.MessageAttributes.fromInstanceId.StringValue,
        'to',
        params.MessageAttributes.toInstanceId.StringValue
    );

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
AwsAutoscaleProvider.prototype.getMessages = function getMessages(actions, options) {
    const params = {
        QueueUrl: this.providerOptions.sqsUrl,
        MessageAttributeNames: ['All'],
        MaxNumberOfMessages: 10,
        VisibilityTimeout: 7, // wait for longer than the VisibilityTimeout in case another
        WaitTimeSeconds: 15 // host is looking at this message at the same time
    };
    const deferred = q.defer();
    const messages = [];
    const promises = [];
    const attributes = {};
    let message;

    logger.debug('getting messages from', this.providerOptions.sqsUrl);

    if (actions && actions.length === 0) {
        logger.silly('Not interested in any actions.');
        deferred.resolve(messages);
        return deferred.promise;
    }

    this.sqs.receiveMessage(params).promise()
        .then((data) => {
            if (data.Messages) {
                logger.silly('Got', data.Messages.length, 'message(s)');
                for (let i = 0; i < data.Messages.length; i++) {
                    message = data.Messages[i];
                    logger.silly('Message', i.toString(), message.Body);

                    if (actions.indexOf(message.Body) === -1) {
                        logger.silly('Not interested in message action', message.Body);
                    } else {
                        const keys = Object.keys(message.MessageAttributes);
                        for (let j = 0; j < keys.length; j++) {
                            const attribute = keys[j];
                            attributes[attribute] = message.MessageAttributes[attribute].StringValue;
                        }

                        if (options.toInstanceId) {
                            if (attributes.toInstanceId !== options.toInstanceId) {
                                logger.silly(
                                    options.toInstanceId,
                                    'is not interested in messages for',
                                    attributes.toInstanceId
                                );
                            } else {
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
                        }
                    }
                }

                logger.silly('Deleting', promises.length, 'message(s)');
                return q.all(promises);
            }
            logger.silly('no messages');
            return q();
        })
        .then(() => {
            logger.silly('Interested in', messages.length, 'message(s)');
            deferred.resolve(messages);
        })
        .catch((err) => {
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
AwsAutoscaleProvider.prototype.syncComplete = function syncComplete(fromUser, fromPassword) {
    const deferred = q.defer();

    // update the bigIp password
    logger.debug('Updating local password');
    bigIp.password = fromPassword;

    if (this.clOptions.passwordUrl) {
        logger.debug('Updating local password file');
        cryptoUtil.encrypt(KEYS.LOCAL_PUBLIC_KEY_PATH, fromPassword)
            .then((encryptedPassword) => {
                return cloudUtil.writeDataToUrl(encryptedPassword, this.clOptions.passwordUrl);
            })
            .then(() => {
                deferred.resolve();
            })
            .catch((err) => {
                logger.warn('Unable to update password URL', this.clOptions.passwordUrl, err);
                deferred.reject(err);
            });
    } else {
        deferred.resolve();
    }

    return deferred.promise;
};

function getTemporaryCredentials(providerOptions, sessionName) {
    const params = {
        RoleArn: providerOptions.roleArn.trim(),
        ExternalId: providerOptions.externalId.trim(),
        RoleSessionName: sessionName
    };
    Aws.config.credentials = new Aws.TemporaryCredentials(params);
    return q();
}

/**
 * Reads the iid doc (generated by AWS) and returns data in a map
 */
function getIidDoc() {
    const deferred = q.defer();
    const filename = '/shared/vadc/aws/iid-document';

    fs.stat(filename, (fsStatErr) => {
        if (fsStatErr && fsStatErr.code === 'ENOENT') {
            logger.debug('No iid doc found');
            deferred.resolve({});
        } else if (fsStatErr) {
            const message = `Error reading iid doc: ${fsStatErr.code}`;
            logger.info(message);
            deferred.reject(new Error(message));
        } else {
            fs.readFile(filename, (err, data) => {
                if (err) {
                    deferred.reject(err);
                } else {
                    deferred.resolve(JSON.parse(data.toString()));
                }
            });
        }
    });

    return deferred.promise;
}

/**
 * Reads info about this instance from AWS
 */
function getAutoScalingInstanceInfo(autoscaling, instanceId) {
    return autoscaling.describeAutoScalingInstances({ InstanceIds: [instanceId] }).promise()
        .then((data) => {
            return data.AutoScalingInstances[0];
        });
}

/**
 * Gets the AWS autoscaling groups
 *
 * @param {Object} autoscaling        - Aws.autoscaling instance
 * @param {String} [autoscaleGroupId] - Limit to just this autoscale group Id
 *
 * @returns {Promise} A promise which is resolved with all of the autoscale groups
 *                    for this account (or autoscaleGroupId) or rejected if an
 *                    error occurs
 */
function getAutoscalingGroups(autoscaling, autoscaleGroupId) {
    const deferred = q.defer();
    const params = {};

    const accumulatedResults = [];

    if (autoscaleGroupId) {
        params.AutoScalingGroupNames = [autoscaleGroupId];
    }

    const accumulateResults = function accumulateResults(data) {
        data.AutoScalingGroups.forEach((autoscalingGroup) => {
            accumulatedResults.push(autoscalingGroup);
        });
    };

    const getNextSet = function getNextSet(nextToken) {
        if (nextToken) {
            params.NextToken = nextToken;
        }

        autoscaling.describeAutoScalingGroups(params, (err, data) => {
            if (err) {
                deferred.reject(err);
            } else {
                accumulateResults(data, accumulatedResults);
                if (data.NextToken) {
                    getNextSet(data.NextToken);
                } else {
                    deferred.resolve(accumulatedResults);
                }
            }
        });
    };

    getNextSet();

    return deferred.promise;
}

/**
 * Gets our view of the current instances
 *
 * @param {Object} s3 - Aws.s3 instance
 * @param {String} s3Bucket - Name of S3 bucket storing our database
 *
 * @returns {Object} Object containing a dictionary of S3 objects keyed by Instance IDs
 */
function getInstancesFromDb(s3, s3Bucket) {
    const deferred = q.defer();
    const instances = {};
    const params = {
        Bucket: s3Bucket,
        Prefix: INSTANCES_FOLDER
    };
    const getPromises = [];
    const prefixLength = params.Prefix.length;

    s3.listObjectsV2(params).promise()
        .then((data) => {
            logger.silly('getInstancesFromDb: S3 bucket size:', data.Contents.length);

            data.Contents.forEach((element) => {
                const instanceId = element.Key.substr(prefixLength);
                if (instanceId) {
                    getPromises.push(getStoredInstance(s3, s3Bucket, element.Key));
                }
            });

            q.all(getPromises)
                .then((responses) => {
                    logger.debug('getInstancesFromDb: instances:', responses);

                    for (let i = 0; i < responses.length; i++) {
                        if (responses[i]) {
                            instances[responses[i].instanceId] = responses[i].data;
                        }
                    }

                    deferred.resolve(instances);
                });
        })
        .catch((err) => {
            deferred.reject(err);
        });

    return deferred.promise;
}

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
function getInstancesFromEc2(ec2, options) {
    const deferred = q.defer();
    const params = {};
    const filters = [];
    const ec2Instances = [];

    if (options.instanceIds && options.instanceIds.length > 0) {
        params.InstanceIds = options.instanceIds;
    }

    if (options.tags && options.tags.length > 0) {
        options.tags.forEach((tag) => {
            filters.push({
                Name: `tag:${tag.key}`,
                Value: tag.value
            });
        });

        params.Filters = filters;
    }

    if (params.InstanceIds || params.Filters) {
        ec2.describeInstances(params).promise()
            .then((data) => {
                if (data.Reservations) {
                    data.Reservations.forEach((reservation) => {
                        if (reservation.Instances) {
                            reservation.Instances.forEach((instance) => {
                                ec2Instances.push(instance);
                            });
                        }
                    });
                }
                deferred.resolve(ec2Instances);
            })
            .catch((err) => {
                deferred.reject(err);
            });
    } else {
        deferred.resolve(ec2Instances);
    }

    return deferred.promise;
}

function getStoredInstance(s3, s3Bucket, key) {
    const deferred = q.defer();
    const prefixLength = INSTANCES_FOLDER.length;

    let mungedKey = key;
    if (!mungedKey.startsWith(INSTANCES_FOLDER)) {
        mungedKey = INSTANCES_FOLDER + mungedKey;
    }

    logger.silly('Getting stored instance', mungedKey);

    getObject(s3, s3Bucket, mungedKey)
        .then((data) => {
            const instanceId = mungedKey.substr(prefixLength);
            let parsed;

            try {
                parsed = JSON.parse(data);
                deferred.resolve({
                    instanceId,
                    data: parsed
                });
            } catch (err) {
                deferred.reject(new Error(`getObject: ${err}`));
            }
        })
        .catch(() => {
            logger.silly('Error caught getting stored instance.');
            deferred.resolve();
        });
    return deferred.promise;
}

/**
 * Generic S3 listObjectsV2
 *
 * @param {Aws.s3}  s3       - Aws.S3 instance
 * @param {String}  s3Bucket - Aws S3 bucket indentifier
 * @param {String}  [prefix] - Prefix for listObjectsV2
 *
 * @returns {Promise} Promise which will be resolved with the data
 */
function listObjects(s3, s3Bucket, prefix) {
    const params = {
        Bucket: s3Bucket,
    };

    if (prefix) {
        params.Prefix = prefix;
    }

    const doList = function () {
        const deferred = q.defer();

        s3.listObjectsV2(params).promise()
            .then((data) => {
                deferred.resolve(data);
            })
            .catch((err) => {
                deferred.reject(err);
            });
        return deferred.promise;
    };

    return cloudUtil.tryUntil(this, cloudUtil.MEDIUM_RETRY, doList);
}

/**
 * Generic S3 getObject
 *
 * @param {Aws.s3}  s3       - Aws.S3 instance
 * @param {String}  s3Bucket - Aws S3 bucket indentifier
 * @param {String}  key      - key for data
 *
 * @returns {Promise} Promise which will be resolved with the data
 */
function getObject(s3, s3Bucket, key) {
    const params = {
        Bucket: s3Bucket,
        Key: key
    };

    logger.silly('getting object', params);

    const doGet = function () {
        const deferred = q.defer();

        s3.getObject(params).promise()
            .then((data) => {
                deferred.resolve(data.Body);
            })
            .catch((err) => {
                deferred.reject(err);
            });
        return deferred.promise;
    };

    // Even with the built-in S3 retry options, we still see failures
    // occasionally so do our own retry
    return cloudUtil.tryUntil(this, cloudUtil.MEDIUM_RETRY, doGet);
}

/**
 * Generic S3 putObject
 *
 * @param {Aws.s3}                                            s3       - Aws.S3 instance
 * @param {Aws.s3 bucket}                                     s3Bucket - Aws S3 bucket indentifier
 * @param {String}                                            key      - key for data
 * @param {Buffer, Typed Array, Blob, String, ReadableStream} [data]   - data
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
function putObject(s3, s3Bucket, key, data) {
    const params = {
        Bucket: s3Bucket,
        Key: key
    };

    if (data) {
        params.Body = data;
    }

    const doPut = function () {
        const deferred = q.defer();

        s3.putObject(params).promise()
            .then((response) => {
                deferred.resolve(response);
            })
            .catch((err) => {
                deferred.reject(err);
            });

        return deferred.promise;
    };

    return cloudUtil.tryUntil(this, cloudUtil.SHORT_RETRY, doPut);
}

/**
 * Generic S3 deleteObject
 *
 * @param {Aws.s3}        s3               - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket         - Aws S3 bucket indentifier
 * @param {String[]}      keys             - Array of keys to delete
 * @param {Object}        [options]        - Optional parameters
 * @param {Boolean}       [options.noWait] - Whether or not to wait for completion before returning.
 *                                           Default is to wait.
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
function deleteObjects(s3, s3Bucket, keys, options) {
    const keyParams = [];
    let params;

    const noWait = options ? options.noWait : false;

    if (keys.length > 0) {
        keys.forEach((key) => {
            keyParams.push({ Key: key });
        });

        params = {
            Bucket: s3Bucket,
            Delete: {
                Objects: keyParams
            }
        };

        const doDelete = function () {
            const deferred = q.defer();

            s3.deleteObjects(params).promise()
                .then((data) => {
                    deferred.resolve(data);
                })
                .catch((err) => {
                    deferred.reject(err);
                });
            return deferred.promise;
        };

        if (noWait) {
            doDelete();
            return q();
        }
        return cloudUtil.tryUntil(this, cloudUtil.SHORT_RETRY, doDelete);
    }

    return q();
}

/**
 * Deletes the oldest objects in a bucket
 *
 * @param {Aws.s3}        s3           - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket     - Aws S3 bucket indentifier
 * @param {String}        keyPrefix    - Prefix for keys (the folder in which object are stored)
 * @param {Number}        maxCopies    - Maximum number of object to keep
 * @param {String}        [filePrefix] - Common prefix for files. Default is to examine full file name
 */
function deleteOldestObjects(s3, s3Bucket, keyPrefix, maxCopies, filePrefix) {
    logger.silly('deleting oldest objects', keyPrefix, filePrefix);
    return listObjects(s3, s3Bucket, keyPrefix)
        .then((data) => {
            let mungedKeyPrefix = keyPrefix;
            let objectsToCheck;

            if (!mungedKeyPrefix.endsWith('/')) {
                mungedKeyPrefix = `${mungedKeyPrefix}/`;
            }

            if (!filePrefix) {
                objectsToCheck = data.Contents;
            } else {
                const totalPrefix = `${mungedKeyPrefix}${filePrefix}`;
                objectsToCheck = data.Contents.filter((item) => {
                    return item.Key.startsWith(totalPrefix);
                });
            }

            logger.silly('objects to check:', objectsToCheck.length);

            if (objectsToCheck.length > maxCopies) {
                const keysToDelete = [];

                // Sort so that oldest is first
                objectsToCheck.sort((a, b) => {
                    if (a.LastModified < b.LastModified) {
                        return -1;
                    } else if (b.LastModified < a.LastModified) {
                        return 1;
                    }
                    return 0;
                });

                for (let i = 0; i < objectsToCheck.length - maxCopies; i++) {
                    keysToDelete.push(objectsToCheck[i].Key);
                }

                logger.silly('keysToDelete', keysToDelete);

                return deleteObjects(s3, s3Bucket, keysToDelete);
            }

            return q();
        })
        .catch((err) => {
            logger.info('Error deleting old UCS files', err);
            return q.reject(err);
        });
}

function setInstanceProtection(autoscaling, instanceId, autoscaleGroupId, status) {
    const deferred = q.defer();

    const params = {
        AutoScalingGroupName: autoscaleGroupId,
        InstanceIds: [instanceId],
        ProtectedFromScaleIn: status
    };

    autoscaling.setInstanceProtection(params, (err, data) => {
        if (err) {
            deferred.reject(err);
        } else {
            deferred.resolve(data);
        }
    });

    return deferred.promise;
}

function getStackIdFromAutoscaleGroup(autoscaleGroup) {
    const tags = autoscaleGroup.Tags;
    for (let i = 0; i < tags.length; i++) {
        if (tags[i].Key === STACK_ID_TAG) {
            return tags[i].Value;
        }
    }
    logger.info(
        'Cannot find stack id for autoscale group',
        autoscaleGroup.AutoScalingGroupName
    );
    return '';
}

function getSecret(secretId, accessKeyId) {
    const hash = crypto.createHash('sha512');
    hash.update(accessKeyId);
    return localCryptoUtil.decryptDataFromRestStorage(secretId, hash.digest('hex'))
        .then((data) => {
            return data.secretAccessKey;
        })
        .catch((err) => {
            logger.info('Error getting secret', err && err.message ? err.message : err);
            return q.reject(err);
        });
}

module.exports = AwsAutoscaleProvider;
