/**
 * Copyright 2016 F5 Networks, Inc.
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

var MASTER_FILE_PATH = "/config/cloud/aws/master";

var AbstractAutoscaleProvider;
var BigIp;

var logger;

// In production we should be installed as a node_module under f5-cloud-libs
// In test, that will not be the case, so use our dev dependency version
// of f5-cloud-libs
try {
    AbstractAutoscaleProvider = require('../../../../f5-cloud-libs').autoscaleProvider;
    BigIp = require('../../../../f5-cloud-libs').bigIp;
}
catch (err) {
    AbstractAutoscaleProvider = require('f5-cloud-libs').autoscaleProvider;
    BigIp = require('f5-cloud-libs').bigIp;
}

util.inherits(AwsAutoscaleProvider, AbstractAutoscaleProvider);

 /**
  * Constructor.
  * @class
  *
  * @param {Ojbect} [options] - Options for the instance
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
 * @param {Object} providerOptions - Provider specific options.
 * @param {String} providerOptions.s3Bucket - S3 bucket to use for storage.
 * @param {Number} [providerOptions.mgmtPort] - BIG-IP management port. Default 443.
 *
 * @returns {Promise} A promise which will be resolved when init is complete.
 */
AwsAutoscaleProvider.prototype.init = function(providerOptions) {

    this.providerOptions = providerOptions;

    if (!this.providerOptions.s3Bucket) {
        return q.reject(new Error('AwsAutoscaleProvider requires providerOptions.s3Bucket'));
    }

    providerOptions.mgmtPort = providerOptions.mgmtPort || "443";
    return getNodeProperties(parseInt(providerOptions.mgmtPort))
        .then(function(response) {
            this.nodeProperties = response;
            Aws.config.update({region: this.nodeProperties.region});
            Aws.config.credentials = new Aws.EC2MetadataCredentials({
                httpOptions: { timeout: 5000 },
                maxRetries: 10,
                retryDelayOptions: { base: 300 }
            });

            this.autoscaling = new Aws.AutoScaling();
            this.s3 = new Aws.S3();
            this.ec2 = new Aws.EC2();

            this.launchConfigMap = {}; // Map of instanceId to launch configuration name

            this.launchConfigurationName = '';
        }.bind(this));
};

/**
 * Gets the instance ID of this instance
 *
 * @returns {String} The instance ID of this instance
 */
AwsAutoscaleProvider.prototype.getInstanceId = function() {
    return this.nodeProperties.instanceId;
};

/**
 * Gets info for each instance
 *
 * @returns {Object} Dictionary of instance info keyed by instance ID. Instance info is
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
 * @param {Object} instances - Dictionary of instances as returned by getInstances
 *
 * @returns {String} Instance ID of the elected master
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
 * Determines if a given instanceId is a valid master
 *
 * Checks that the launch configuration of the specified master matches
 * our launch configuration.
 *
 * @param {String} instanceId - Instance ID to validate as a valid master.
 *
 * @returns {Boolean} Wether or not the given instanceId is a valid master
 */
AwsAutoscaleProvider.prototype.isValidMaster = function(instanceId) {
    if (this.launchConfigMap[instanceId] === this.launchConfigurationName) {
        return q(true);
    }

    return q(false);
};

/**
 * Saves instance info
 *
 * @param {Object} Instance information as returned by getInstances
 */
AwsAutoscaleProvider.prototype.putInstance = function(instance) {
    var deferred = q.defer();

    logger.debug('putInstance: instance:', instance);

    var params = {
        Bucket: this.providerOptions.s3Bucket,
        Key: this.nodeProperties.instanceId,
        Body: JSON.stringify(instance)  // body from above
    };

    this.s3.putObject(params, function(err, data) {
        if (err) {
            deferred.reject(err);
        } else {
            if (instance.isMaster) {
                // Mark ourself as master on disk so other scripts have access to this info
                fs.closeSync(fs.openSync(MASTER_FILE_PATH, 'w'));
            }
            deferred.resolve(data);
        }
    });

    return deferred.promise;
};

/**
 * Turns on instance protection for the given instance ID
 */
AwsAutoscaleProvider.prototype.setInstanceProtection = function(instanceId) {
    instanceId = instanceId || this.getInstanceId();
    return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, true);
};

/**
 * Turns off instance protection for the given instance ID
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
 * Output an object containing all settings for this F5 device
 *
 * Settings will be gathered from:
 *     1) /shared/vadc/aws/iid-document
 *     2) tmsh: hostname, autoscaleGroupId
 *
 * @param {Number} mgmtPort - Management port for BIG-IP
 */
var getNodeProperties = function(mgmtPort) {
    var deferred = q.defer();
    var properties = {};
    var bigIp = new BigIp('localhost', 'admin', 'dummypass', {port: mgmtPort, logger: logger});

    getIidDoc()
        .then(function(response) {

            logger.debug('getNodeProperties: iidDoc:', response);

            properties.mgmtIp = response.privateIp;
            properties.privateIp = response.privateIp;
            properties.instanceId = response.instanceId;
            properties.region = response.region;

            return bigIp.list('/tm/sys/global-settings');
        })
        .then(function(res) {
            properties.hostname = res.hostname;
            return bigIp.list('/tm/sys/autoscale-group');
        })
        .then(function(res) {
            properties.autoscaleGroupId = res.autoscaleGroupId;
            deferred.resolve(properties);
        })
        .catch(function(err) {
            deferred.reject(err);
        })
        .done();

    return deferred.promise;
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
    var params = {Bucket: s3Bucket};
    var getPromises = [];
    var keysToDelete = [];

    s3.listObjectsV2(params, function (err, data) {
        if (err) {
            logger.error('s3.listObjectsV2:', err);
            deferred.reject(err);
        }
        else {
            logger.debug('getRegistgeredInstances: S3 bucket size:', data.Contents.length);

            data.Contents.forEach(function (element) {
                logger.debug('getRegistgeredInstances: comparing with instanceIds, element.Key:', element.Key);
                if (instanceIds.indexOf(element.Key) !== -1) {
                    getPromises.push(getObject(s3, s3Bucket, element.Key));
                }
                else {
                    logger.debug('getRegistgeredInstances: bucket item not in instanceIds, mark for removal from S3');
                    keysToDelete.push(element.Key);
                }
            });
        }

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
            })
            .catch(function(err) {
                deferred.reject(err);
            });
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

var getObject = function(s3, s3Bucket, key) {
    var deferred = q.defer();
    var params = {Bucket: s3Bucket, Key: key};
    logger.debug('getObject: params:', params);
    s3.getObject(params, function (err, data) {
        var parsed;
        var instanceId;
        if (err) {
            deferred.reject(err);
        }
        else {
            try {
                parsed = JSON.parse(data.Body.toString());
                // 'this' is set by the Aws SDK to a context containing the request
                instanceId = this.request.httpRequest.path.substr(1);
                logger.debug('getObject:', instanceId, JSON.stringify(parsed));
                deferred.resolve({instanceId: instanceId, data: parsed});
            }
            catch (err) {
                logger.error('getObject: err:', err);
                deferred.reject(err);
            }
        }
    });

    return deferred.promise;
};

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

        s3.deleteObjects(params, function(err, data) {
            if (err) {
                deferred.reject(err);
            }
            else {
                logger.debug('deleteObjects: success data:', data);
                deferred.resolve(data);
            }
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