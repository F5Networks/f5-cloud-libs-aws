/**
 * Copyright 2016, 2017 F5 Networks, Inc.
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

var logger;

const MASTER_FILE_PATH = "/config/cloud/aws/master";
const CREDENTIALS_KEY = "credentials/master";
const INSTANCES_FOLDER = "instances/";

// In production we should be installed as a node_module under f5-cloud-libs
// In test, that will not be the case, so use our dev dependency version
// of f5-cloud-libs
try {
    AbstractAutoscaleProvider = require('../../../../f5-cloud-libs').autoscaleProvider;
    BigIp = require('../../../../f5-cloud-libs').bigIp;
    cloudUtil = require('../../../../f5-cloud-libs').util;
}
catch (err) {
    AbstractAutoscaleProvider = require('f5-cloud-libs').autoscaleProvider;
    BigIp = require('f5-cloud-libs').bigIp;
    cloudUtil = require('f5-cloud-libs').util;
}

util.inherits(AwsAutoscaleProvider, AbstractAutoscaleProvider);

 /**
  * Constructor.
  * @class
  *
  * @param {Ojbect} [options] - Options for the instance.
  * @param {Object} [options.clOptions] - Command line options if called from a script.
  * @param {Logger} [options.logger] - Logger to use. Default no logging.
  */
function AwsAutoscaleProvider(options) {
    AwsAutoscaleProvider.super_.call(this, options);
    logger = this.logger;
}

/**
 * Initialize class
 *
 * Override for implementation specific initialization needs (read info
 * from cloud provider, read database, etc.). Called at the start of
 * processing.
 *
 * @param {Object}  providerOptions            - Provider specific options.
 * @param {String}  providerOptions.s3Bucket   - S3 bucket to use for storage.
 * @param {Number}  [providerOptions.mgmtPort] - BIG-IP management port. Default 443.
 * @param {Object}  [options]                  - Options for this instance.
 * @param {Boolean} [options.autoscale]        - Whether or not this instance will be used for autoscaling.
 *
 * @returns {Promise} A promise which will be resolved when init is complete.
 */
AwsAutoscaleProvider.prototype.init = function(providerOptions, options) {

    var bigIp;

    this.providerOptions = providerOptions;
    options = options || {};

    if (!this.providerOptions.s3Bucket) {
        return q.reject(new Error('AwsAutoscaleProvider requires providerOptions.s3Bucket'));
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

            bigIp = new BigIp('localhost',
                              this.clOptions.user,
                              this.clOptions.password || this.clOptions.passwordUrl,
                              {
                                  port: parseInt(providerOptions.mgmtPort),
                                  logger: logger,
                                  passwordIsUrl: typeof this.clOptions.passwordUrl !== 'undefined'
                              });
            return bigIp.list('/tm/sys/global-settings');
        }.bind(this))
        .then(function(response) {
            this.nodeProperties.hostname = response.hostname;

            Aws.config.update({region: this.nodeProperties.region});
            Aws.config.credentials = new Aws.EC2MetadataCredentials({
                httpOptions: { timeout: 5000 },
                maxRetries: 10,
                retryDelayOptions: { base: 300 }
            });

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
        }.bind(this));
};

/**
 * Gets the instance ID of this instance
 *
 * @returns {String} The instance ID of this instance.
 */
AwsAutoscaleProvider.prototype.getInstanceId = function() {
    return this.nodeProperties.instanceId;
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

                    return getEC2Instances(this.ec2, missingInstanceIds);
                }.bind(this))
                .then(function(response) {
                    for (instanceId in response) {
                        instances[instanceId] = response[instanceId];
                        instances[instanceId].isMaster = false;
                    }
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
        return getObject(this.s3, this.providerOptions.s3Bucket, CREDENTIALS_KEY)
            .then(function(data) {
                var masterBigIp;
                credentials = JSON.parse(data);
                logger.debug("Got master credentials from S3. Validating...");
                masterBigIp = new BigIp(mgmtIp, credentials.username, credentials.password, {port: mgmtPort, logger: logger});
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
    var password;

    password = typeof this.clOptions.passwordUrl !== 'undefined' ? cloudUtil.getPasswordFromUrl(this.clOptions.passwordUrl) : this.clOptions.password;
    putObject(this.s3,
              this.providerOptions.s3Bucket,
              CREDENTIALS_KEY,
              JSON.stringify({
                  username: this.clOptions.user,
                  password: password
              }))
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
    var deferred = q.defer();

    logger.debug('putInstance: instance:', instance);

    putObject(this.s3,
              this.providerOptions.s3Bucket,
              INSTANCES_FOLDER + this.nodeProperties.instanceId,
              JSON.stringify(instance))
        .then(function(data) {
            if (instance.isMaster) {
                // Mark ourself as master on disk so other scripts have access to this info
                fs.closeSync(fs.openSync(MASTER_FILE_PATH, 'w'));
                deferred.resolve(data);
            }
            else {
                deferred.resolve();
            }
        })
        .catch(function(err) {
            deferred.reject(new Error('Unable to putInstance:' + err));
        });

    return deferred.promise;
};

/**
 * Turns on instance protection for the given instance ID
 *
 * @param {String} [instanceId] - Instance ID of instnace to protect. Default instance ID of self.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.setInstanceProtection = function(instanceId) {
    instanceId = instanceId || this.getInstanceId();
    return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, true);
};

/**
 * Turns off instance protection for the given instance ID
 *
 * @param {String} [instanceId] - Instance ID of instnace to un-protect. Default instance ID of self.
 *
 * @returns {Promise} A promise which will be resolved when processing is complete.
 */
AwsAutoscaleProvider.prototype.unsetInstanceProtection = function(instanceId) {
    instanceId = instanceId || this.getInstanceId();
    return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, false);
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

var getEC2Instances = function(ec2, instanceIds) {
    var deferred = q.defer();
    var params = {
        InstanceIds: instanceIds
    };
    var ec2Instances = {};
    var instanceId;

    if (instanceIds.length > 0) {
        ec2.describeInstances(params, function(err, data) {
            if (err) {
                deferred.reject(err);
            }
            else {
                if (data.Reservations) {
                    data.Reservations.forEach(function(reservation) {
                        if (reservation.Instances) {
                            reservation.Instances.forEach(function(instance) {
                                instanceId = instance.InstanceId;
                                ec2Instances[instanceId] = {
                                    privateIp: instance.PrivateIpAddress,
                                    mgmtIp: instance.PrivateIpAddress,
                                    hostname: instance.PrivateDnsName
                                };
                            });
                        }
                    });
                }

                deferred.resolve(ec2Instances);
            }
        });
    }
    else {
        deferred.resolve();
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
 * Generic S3 getObject
 *
 * Wrap in a q promise so we can pass this function to other
 * functions that expect a 'done' method.
 *
 * @param {Aws.s3}        s3       - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket - Aws S3 bucket indentifier
 * @param {String}        key      - key for data
 *
 * @returns {Promise} Promise which will be resolved with the data
 */
var getObject = function(s3, s3Bucket, key) {
    var deferred = q.defer();
    var params = {
        Bucket: s3Bucket,
        Key: key
    };

    s3.getObject(params).promise()
        .then(function(data) {
            deferred.resolve(data.Body.toString());
        })
        .catch(function(err) {
            deferred.reject(err);
        });

    return deferred.promise;
};

/**
 * Generic S3 putObject
 *
 * Wrap in a q promise so we can pass this function to other
 * functions that expect a 'done' method.
 *
 * @param {Aws.s3}        s3       - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket - Aws S3 bucket indentifier
 * @param {String}        key      - key for data
 * @param {String}        data     - String representation of data
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
var putObject = function(s3, s3Bucket, key, data) {
    var deferred = q.defer();
    var params = {
        Bucket: s3Bucket,
        Key: key,
        Body: data
    };

    s3.putObject(params).promise()
        .then(function(data) {
            deferred.resolve(data);
        })
        .catch(function(err) {
            deferred.reject(err);
        });

    return deferred.promise;
};

/**
 * Generic S3 deleteObject
 *
 * Wrap in a q promise so we can pass this function to other
 * functions that expect a 'done' method.
 *
 * @param {Aws.s3}        s3       - Aws.S3 instance
 * @param {Aws.s3 bucket} s3Bucket - Aws S3 bucket indentifier
 * @param {String[]}      keys     - Array of keys to delete
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 */
var deleteObjects = function(s3, s3Bucket, keys) {
    var deferred = q.defer();
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

        s3.deleteObjects(params).promise()
            .then(function(data) {
                deferred.resolve(data);
            })
            .catch(function(err) {
                deferred.reject(err);
            });
    }
    else {
        deferred.resolve();
    }

    return deferred.promise;
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