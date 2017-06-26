/**
 * Copyright 2016 - 2017 F5 Networks, Inc.
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
var AbstractAutoscaleProvider;
var BigIp;
var Logger;
var bigIp;
var logger;

const CREDENTIALS_KEY = "credentials/master";
const INSTANCES_FOLDER = "instances/";
const BACKUP_FOLDER = "backup/";
const AWS_RETRY_OPTIONS = {
    httpOptions: { timeout: 120000 },
    maxRetries: 20,
    retryDelayOptions: { base: 300 }
};

// In production we should be installed as a node_module under f5-cloud-libs
// In test, that will not be the case, so use our dev dependency version
// of f5-cloud-libs
try {
    AbstractAutoscaleProvider = require('../../../../f5-cloud-libs').autoscaleProvider;
    BigIp = require('../../../../f5-cloud-libs').bigIp;
    Logger = require('../../../../f5-cloud-libs').logger;
    cloudUtil = require('../../../../f5-cloud-libs').util;
}
catch (err) {
    AbstractAutoscaleProvider = require('f5-cloud-libs').autoscaleProvider;
    BigIp = require('f5-cloud-libs').bigIp;
    Logger = require('f5-cloud-libs').logger;
    cloudUtil = require('f5-cloud-libs').util;
}

// temporarily here till we move it to util.js
cloudUtil.MEDIUM_RETRY = {
    maxRetries: 30,
    retryIntervalMs: 2000
};

util.inherits(AwsAutoscaleProvider, AbstractAutoscaleProvider);

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
 * @param {Object}  providerOptions                           - Provider specific options.
 * @param {String}  providerOptions.s3Bucket                  - S3 bucket to use for storage.
 * @param {Number}  [providerOptions.mgmtPort]                - BIG-IP management port. Default 443.
 * @param {String}  [providerOptions.roleArn]                 - ARN of role to assume.
 * @param {String}  [providerOptions.externalId]              - External Id for role to assume.
 * @param {Object}  [options]                                 - Options for this instance.
 * @param {Boolean} [options.autoscale]                       - Whether or not this instance will be used for autoscaling.
 *
 * @returns {Promise} A promise which will be resolved when init is complete.
 */
AwsAutoscaleProvider.prototype.init = function(providerOptions, options) {

    this.providerOptions = providerOptions = providerOptions || {};
    options = options || {};

    if (!this.providerOptions.s3Bucket && options.autoscale) {
        return q.reject(new Error('AwsAutoscaleProvider requires providerOptions.s3Bucket when used for autoscaling'));
    }

    providerOptions.mgmtPort = providerOptions.mgmtPort || "443";

    this.nodeProperties = {};
    this.launchConfigMap = {}; // Map of instanceId to launch configuration name
    this.launchConfigurationName = '';

    return getIidDoc()
        .then(function(response) {
            this.nodeProperties.mgmtIp = response.privateIp;
            this.nodeProperties.privateIp = response.privateIp;
            this.nodeProperties.instanceId = response.instanceId;
            this.nodeProperties.region = response.region;

            if (this.clOptions.user && this.clOptions.password) {
                bigIp = new BigIp({loggerOptions: this.loggerOptions});
                return bigIp.init('localhost',
                                  this.clOptions.user,
                                  this.clOptions.password || this.clOptions.passwordUrl,
                                  {
                                      port: parseInt(providerOptions.mgmtPort),
                                      passwordIsUrl: typeof this.clOptions.passwordUrl !== 'undefined'
                                  });
            }
        }.bind(this))
        .then(function() {
            if (bigIp) {
                return bigIp.list('/tm/sys/global-settings');
            }
        }.bind(this))
        .then(function(response) {
            if (response) {
                // TODO: do we need this - doesn't seem to be used anywhere
                this.nodeProperties.hostname = response.hostname;
            }

            Aws.config.update({region: providerOptions.region || this.nodeProperties.region});
            Aws.config.update(AWS_RETRY_OPTIONS);
            Aws.config.credentials = new Aws.EC2MetadataCredentials(AWS_RETRY_OPTIONS);

            if (providerOptions.roleArn && !(providerOptions.roleArn === "''" || providerOptions.roleArn === '""')) {
                return getTemporaryCredentials(providerOptions, this.nodeProperties.instanceId);
            }
        }.bind(this))
        .then(function() {
            this.s3 = new Aws.S3();
            this.ec2 = new Aws.EC2();
            this.autoscaling = new Aws.AutoScaling();

            if (options.autoscale) {
                return getAutoScalingInstanceInfo(this.autoscaling, this.nodeProperties.instanceId);
            }
        }.bind(this))
        .then(function(response) {

            if (options.autoscale) {
                this.nodeProperties.autoscaleGroupId = response.AutoScalingGroupName;

                // We also need to write this to BIG-IP to signal it to collect metrics for CloudWatch
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
        return q.reject(new Error("Invalid ARN. Fomat should be arn:aws:s3:::bucket_name/key_name"));
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
 * @returns {Promise} A promise which will be resolved with a dictionary of instances
 *                   {
 *                       isMaster: <Boolean>,
 *                       hostname: <String>,
 *                       mgmtIp: <String>,
 *                       privateIp: <String>
 *                   }
 */
AwsAutoscaleProvider.prototype.getInstances = function() {
    var deferred = q.defer();
    var numInstances = 0;
    var params = {
        AutoScalingGroupNames: [this.nodeProperties.autoscaleGroupId]
    };
    var instances = {};
    var instanceIds = [];
    var missingInstanceIds = [];
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
            numInstances = autoscalingGroup.Instances.length;
            this.launchConfigurationName = autoscalingGroup.LaunchConfigurationName;
            logger.debug('getInstances: Number of instances in autoscale group:', numInstances);
            logger.debug('getInstances: launchConfigurationName:', this.launchConfigurationName);
            autoscalingGroup.Instances.forEach(function(instance) {
                instanceId = instance.InstanceId;
                logger.debug('getInstances: instance:', instanceId);
                this.launchConfigMap[instanceId] = instance.LaunchConfigurationName;
                instances[instanceId] = {};
                instanceIds.push(instanceId);
            }.bind(this));

            // Now get info from our database
            getRegisteredInstances(this.s3, this.providerOptions.s3Bucket, Object.keys(this.launchConfigMap))
                .then(function(registeredInstances) {

                    // Copy in info from our db and find missing instances
                    for (i = 0; i < instanceIds.length; ++i) {
                        instanceId = instanceIds[i];
                        if (registeredInstances[instanceId]) {
                            instances[instanceId] = registeredInstances[instanceId];
                        }
                        else {
                            missingInstanceIds.push(instanceId);
                        }
                    }

                    return getEC2Instances(this.ec2, {instanceIds: missingInstanceIds});
                }.bind(this))
                .then(function(response) {

                    response.forEach(function(instance) {
                        instances[instance.InstanceId] = {
                            privateIp: instance.PrivateIpAddress,
                            mgmtIp: instance.PrivateIpAddress,
                            hostname: instance.PrivateDnsName,
                            isMaster: false
                        };
                    });
                    deferred.resolve(instances);
                })
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

    logger.debug('electMaster: instanceIds:', instanceIds);
    logger.debug('electMaster: lowestIpToNumber:', lowestIpToNumber);
    logger.debug('electMaster: index of lowestIp:', index);
    logger.debug('electMaster: electedMaster:', electedMaster);

    deferred.resolve(instanceId);

    return deferred.promise;
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
 * Saves instance info
 *
 * @param {Object} Instance information as returned by getInstances.
 *
 * @returns {Promise} A promise which will be resolved with instance info.
 */
AwsAutoscaleProvider.prototype.putInstance = function(instance) {
    logger.debug('putInstance: instance:', instance);

    return putObject(this.s3,
        this.providerOptions.s3Bucket,
        INSTANCES_FOLDER + this.nodeProperties.instanceId,
        JSON.stringify(instance));
};

/**
 * Turns on instance protection for the given instance ID
 *
 * @param {String} [instanceId] - Instance ID of instnace to protect. Default instance ID of self.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.setInstanceProtection = function(instanceId) {
    return (instanceId ? q(instanceId) : this.getInstanceId())
        .then(function(instanceId) {
            return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, true);
        }.bind(this));
};

/**
 * Turns off instance protection for the given instance ID
 *
 * @param {String} [instanceId] - Instance ID of instnace to un-protect. Default instance ID of self.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.unsetInstanceProtection = function(instanceId) {
    return (instanceId ? q(instanceId) : this.getInstanceId())
        .then(function(instanceId) {
            return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, false);
        }.bind(this));
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
 * @param {String[]} instanceIds - Array of instanceIds
 *
 * @returns {Object} Object containing a dictionary of S3 objects keyed by Instance IDs
 */
var getRegisteredInstances = function(s3, s3Bucket, instanceIds) {
    var deferred = q.defer();
    var s3Dict = {};
    var params = {
        Bucket: s3Bucket,
        Prefix: INSTANCES_FOLDER
    };
    var getPromises = [];
    var keysToDelete = [];
    var prefixLength = params.Prefix.length;

    s3.listObjectsV2(params).promise()
        .then(function(data) {
            logger.debug('getRegistgeredInstances: S3 bucket size:', data.Contents.length);

            data.Contents.forEach(function (element) {
                var instanceId = element.Key.substr(prefixLength);
                logger.debug('getRegistgeredInstances: comparing with instanceIds, element.Key:', instanceId);
                if (instanceIds.indexOf(instanceId) !== -1) {
                    getPromises.push(getStoredInstance(s3, s3Bucket, element.Key));
                }
                else {
                    logger.debug('getRegistgeredInstances: bucket item not in instanceIds, mark for removal from S3');
                    keysToDelete.push(element.Key);
                }
            });

            q.all(getPromises)
                .then(function(responses) {
                    var i;

                    logger.debug('getRegistgeredInstances: instances:', responses);

                    for (i = 0; i < responses.length; ++i) {
                        s3Dict[responses[i].instanceId] = responses[i].data;
                    }

                    deleteObjects(s3, s3Bucket, keysToDelete)
                        .then(function() {
                            deferred.resolve(s3Dict);
                        })
                        .catch(function(err) {
                            logger.warn('Failed to delete instances', err);
                            deferred.reject(err);
                        });
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
var getEC2Instances = function(ec2, options) {
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
    return cloudUtil.tryUntil(this, cloudUtil.SHORT_RETRY, doGet);
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
 * @param {Aws.s3}        s3       - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket - Aws S3 bucket indentifier
 * @param {String[]}      keys     - Array of keys to delete
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
var deleteObjects = function(s3, s3Bucket, keys) {
    var keyParams = [];
    var params;

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

        return cloudUtil.tryUntil(this, cloudUtil.SHORT_RETRY, doDelete);
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
