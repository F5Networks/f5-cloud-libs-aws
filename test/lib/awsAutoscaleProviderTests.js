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

var q;
var fsMock;
var awsMock;
var AwsAutoscaleProvider;
var bigIpMock;
var utilMock;
var provider;

var providerOptions = {
    s3Bucket: 'foo',
    sqsUrl: 'bar'
};

var user = 'foo';
var password = 'bar';

var iidDoc;

var instanceId = '1234';
var instances;
var instance1;
var instance2;

var deletedInstances;

var getObjectParams;
var instanceProtectionParams;
var putInstanceId;
var putInstance;

// Our tests cause too many event listeners. Turn off the check.
process.setMaxListeners(0);

module.exports = {
    setUp: function(callback) {
        q = require('q');
        fsMock = require('fs');
        awsMock = require('aws-sdk');
        bigIpMock = require('f5-cloud-libs').bigIp;
        utilMock = require('f5-cloud-libs').util;

        AwsAutoscaleProvider = require('../../lib/awsAutoscaleProvider');

        provider = new AwsAutoscaleProvider({clOptions: {user: user, password: password}});

        awsMock.config = {
            configUpdate: {},
            update: function(config) {
                Object.assign(this.configUpdate,config);
            }
        };

        fsMock.reset = function() {
            iidDoc = undefined;
        };

        fsMock.reset();

        utilMock.DEFAULT_RETRY = utilMock.NO_RETRY;
        utilMock.SHORT_RETRY = utilMock.NO_RETRY;
        utilMock.MEDIUM_RETRY = utilMock.NO_RETRY;

        callback();
    },

    tearDown: function(callback) {
        Object.keys(require.cache).forEach(function(key) {
            delete require.cache[key];
        });
        callback();
    },

    testFeatures: function(test) {
        test.expect(1);
        test.ok(provider.features.FEATURE_MESSAGING);
        test.done();
    },

    testInit: {
        setUp: function(callback) {
            iidDoc = "{}";

            awsMock.AutoScaling.prototype.describeAutoScalingInstances = function() {
                return {
                    promise: function() {
                        var deferred = q.defer();
                        deferred.resolve({
                            AutoScalingInstances: [
                                {
                                    AutoScalingGroupName: 'myAutoscalingGroup'
                                }
                            ]
                        });
                        return deferred.promise;
                    }
                };
            };

            awsMock.S3.prototype.listObjectsV2 = function() {
                return {
                    promise: function() {
                        return q({KeyCount: 1});
                    }
                };
            };

            bigIpMock.prototype.list = function() {
                return {
                    then: function(cb) {
                        cb({hostname: 'myhost'});
                    }
                };
            };

            bigIpMock.prototype.modify = function() {
                return {
                    then: function(cb) {
                        cb();
                    }
                };
            };

            fsMock.readFile = function(filename, cb) {
                var data;

                switch (filename) {
                    case "/shared/vadc/aws/iid-document":
                        data = iidDoc;
                        break;
                }

                cb(null, data);
            };

            callback();
        },

        testGetIidDoc: function(test) {
            iidDoc = {
                privateIp: '1.2.3.4',
                instanceId: 'myInstanceId',
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);

            test.expect(4);
            provider.init(providerOptions)
                .then(function() {
                    test.strictEqual(provider.nodeProperties.mgmtIp, '1.2.3.4');
                    test.strictEqual(provider.nodeProperties.privateIp, '1.2.3.4');
                    test.strictEqual(provider.nodeProperties.instanceId, 'myInstanceId');
                    test.strictEqual(provider.nodeProperties.region, 'myRegion');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testSetRegion: function(test) {
            iidDoc = {
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);

            test.expect(1);
            provider.init(providerOptions)
                .then(function() {
                    test.strictEqual(awsMock.config.configUpdate.region, 'myRegion');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testCreateBucket: {
            setUp: function(callback) {
                awsMock.S3.prototype.listObjectsV2 = function() {
                    return {
                        promise: function() {
                            return q({KeyCount: 0});
                        }
                    };
                };
                callback();
            },

            testCreated: function(test) {
                var putParams;
                awsMock.S3.prototype.putObject = function(params) {
                    putParams = params;
                    return {
                        promise: function() {
                            return q();
                        }
                    };
                };

                test.expect(1);
                provider.init(providerOptions)
                    .then(function() {
                        test.strictEqual(putParams.Key, 'backup/');
                    })
                    .catch(function(err) {
                        test.ok(false, err.message);
                    })
                    .finally(function() {
                        test.done();
                    });
            },

            testListObjectsError: function(test) {
                var errorMessage = 'foobar';
                awsMock.S3.prototype.listObjectsV2 = function() {
                    return {
                        promise: function() {
                            return q.reject(errorMessage);
                        }
                    };
                };

                test.expect(1);
                provider.init(providerOptions)
                    .then(function() {
                        test.ok(false, 'Should have had list objects error');
                    })
                    .catch(function(err) {
                        test.strictEqual(err, errorMessage);
                    })
                    .finally(function() {
                        test.done();
                    });
            },

            testPutObjectError: function(test) {
                var errorMessage = 'foobar';
                awsMock.S3.prototype.putObject = function() {
                    return {
                        promise: function() {
                            return q.reject(errorMessage);
                        }
                    };
                };

                test.expect(1);
                provider.init(providerOptions)
                    .then(function() {
                        test.ok(false, 'Should have had list objects error');
                    })
                    .catch(function(err) {
                        test.strictEqual(err, errorMessage);
                    })
                    .finally(function() {
                        test.done();
                    });

            }
        }
    },

    testGetDataFromUri: {
        setUp: function(callback) {
            provider.s3 = {
                getObject: function(params) {
                    getObjectParams = params;

                    return {
                        promise: function() {
                            var deferred = q.defer();
                            deferred.resolve({Body: 'bucket data'});
                            return deferred.promise;
                        }
                    };
                }
            };

            getObjectParams = undefined;
            callback();
        },

        testBasic: function(test) {
            test.expect(3);
            provider.getDataFromUri('arn:aws:s3:::myBucket/myKey')
                .then(function(data) {
                    test.strictEqual(getObjectParams.Bucket, 'myBucket');
                    test.strictEqual(getObjectParams.Key, 'myKey');
                    test.strictEqual(data, 'bucket data');
                })
                .catch(function(err) {
                    test.ok(false, err);
                })
                .finally(function() {
                    test.done();
                });
        },

        testComplexKey: function(test) {
            test.expect(3);
            provider.getDataFromUri('arn:aws:s3:::myBucket/myFolder/myKey')
                .then(function(data) {
                    test.strictEqual(getObjectParams.Bucket, 'myBucket');
                    test.strictEqual(getObjectParams.Key, 'myFolder/myKey');
                    test.strictEqual(data, 'bucket data');
                })
                .catch(function(err) {
                    test.ok(false, err);
                })
                .finally(function() {
                    test.done();
                });
        },

        testInvalidUri: function(test) {
            test.expect(1);
            provider.getDataFromUri('https://aws.s3.com/myBucket/myKey')
                .then(function() {
                    test.ok(false, 'Should have thrown invalid URI');
                })
                .catch(function(err) {
                    test.notStrictEqual(err.message.indexOf('Invalid URI'), -1);
                })
                .finally(function() {
                    test.done();
                });
        },

        testInvalidArn: function(test) {
            test.expect(1);
            provider.getDataFromUri('arn:aws:s3:::foo/')
                .then(function() {
                    test.ok(false, 'Should have thrown invalid ARN');
                })
                .catch(function(err) {
                    test.notStrictEqual(err.message.indexOf('Invalid ARN'), -1);
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testGetInstances: {
        setUp: function(callback) {

            const INSTANCES_FOLDER = 'instances/';
            provider.providerOptions = providerOptions;
            provider.launchConfigMap = {};

            provider.nodeProperties = {
                instanceId: 'id1',
                hostname: 'missingHostname1',
                mgmtIp: '7.8.9.0',
                privateIp: '10.11.12.13'
            };

            provider.autoscaling = {
                describeAutoScalingGroups: function(params, cb) {
                    var data = {
                        AutoScalingGroups: [
                            {
                                LaunchConfigurationName: 'mainLaunchConfig',
                                Instances: [
                                    {
                                        InstanceId: 'id1',
                                        LaunchConfigurationName: 'id1LaunchConfig'
                                    },
                                    {
                                        InstanceId: 'id2',
                                        LaunchConfigurationName: 'id2LaunchConfig'
                                    }
                                ]
                            }
                        ]
                    };

                    cb(null, data);
                }
            };

            provider.s3 = {
                listObjectsV2: function() {
                    return {
                        promise: function() {
                            var deferred = q.defer();
                            var data = {
                                Contents: [
                                    {
                                        Key: INSTANCES_FOLDER + 'id1'
                                    },
                                    {
                                        Key: INSTANCES_FOLDER + 'id2'
                                    },
                                    {
                                        Key: INSTANCES_FOLDER + 'goneMissing'
                                    }
                                ]
                            };
                            deferred.resolve(data);
                            return deferred.promise;
                        }
                    };
                },

                getObject: function(params) {
                    var data;
                    var deferred;
                    instance1 = {
                        isMaster: false,
                        hostname: 'hostname1',
                        mgmtIp: '1.2.3.4',
                        privateIp: '1.2.3.4',
                        mgmtPort: 1000,
                        adminUser: 'myAdminUser',
                        adminPassword: 'myAdminPassword',
                        providerVisible: true
                    };
                    instance2 = {
                        isMaster: false,
                        hostname: 'hostname2',
                        mgmtIp: '5.6.7.8',
                        privateIp: '5.6.7.8',
                        mgmtPort: 1000,
                        adminUser: 'myAdminUser',
                        adminPassword: 'myAdminPassword',
                        providerVisible: true
                    };

                    switch (params.Key) {
                        case INSTANCES_FOLDER + 'id1':
                            data = {
                                Body: instance1
                            };
                            break;
                        case INSTANCES_FOLDER + 'id2':
                            data = {
                                Body: instance2
                            };
                            break;
                    }

                    data = data || {Body: {}};
                    data.Body = JSON.stringify(data.Body);

                    return {
                        promise: function() {
                            deferred = q.defer();
                            deferred.resolve(data);
                            return deferred.promise;
                        }
                    };
                },

                deleteObjects: function(params) {

                    params.Delete.Objects.forEach(function(element) {
                        deletedInstances.push(element.Key);
                    });

                    return {
                        promise: function() {
                            return q();
                        }
                    };
                }
            };

            provider.ec2 = {
                describeInstances: function() {
                    return {
                        promise: function() {
                            return q({});
                        }
                    };
                }
            };

            provider.revokeLicenses = function() {
                return q();
            };

            deletedInstances = [];

            callback();
        },

        testLaunchConfigurationMap: function(test) {
            test.expect(3);
            provider.getInstances()
                .then(function() {
                    test.strictEqual(provider.launchConfigurationName, 'mainLaunchConfig');
                    test.strictEqual(provider.launchConfigMap.id1, 'id1LaunchConfig');
                    test.strictEqual(provider.launchConfigMap.id2, 'id2LaunchConfig');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testInstanceMap: function(test) {
            test.expect(2);
            provider.getInstances()
                .then(function(instances) {
                    delete instances.id1.lastUpdate;
                    delete instances.id2.lastUpdate;
                    test.deepEqual(instances.id1, instance1);
                    test.deepEqual(instances.id2, instance2);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testInstanceMapMissingInstanceId: function(test) {
            // If an instance ID is missing from the db, we should get it from
            // describe instances
            provider.autoscaling.describeAutoScalingGroups = function(params, cb) {
                var data = {
                    AutoScalingGroups: [
                        {
                            LaunchConfigurationName: 'mainLaunchConfig',
                            Instances: [
                                {
                                    InstanceId: 'id1',
                                    LaunchConfigurationName: 'id1LaunchConfig'
                                },
                                {
                                    InstanceId: 'id2',
                                    LaunchConfigurationName: 'id2LaunchConfig'
                                },
                                {
                                    InstanceId: 'id3',
                                    LaunchConfigurationName: 'id3LaunchConfig'
                                }
                            ]
                        }
                    ]
                };

                cb(null, data);
            };

            provider.ec2.describeInstances = function() {
                return {
                    promise: function() {
                        var deferred = q.defer();
                        var data =  {
                            Reservations: [
                                    {
                                        Instances: [
                                            {
                                                InstanceId: 'id3',
                                                PrivateIpAddress: '7.8.9.0',
                                                PrivateDnsName: 'missingHostname3'
                                            }
                                        ]
                                    }
                                ]
                            };
                            deferred.resolve(data);
                            return deferred.promise;
                    }
                };
            };

            provider.getInstances()
                .then(function(instances) {
                    delete instances.id2.lastUpdate;
                    delete instances.id3.lastUpdate;
                    test.deepEqual(
                       instances.id3,
                       {
                           isMaster: false,
                           hostname: 'missingHostname3',
                           mgmtIp: '7.8.9.0',
                           privateIp: '7.8.9.0',
                           providerVisible: true
                        }
                    );
                    test.deepEqual(instances.id2, instance2);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testNonMastersDeleted: function(test) {
            test.expect(3);
            provider.getInstances()
                .then(function() {
                    test.strictEqual(deletedInstances.length, 2);
                    test.strictEqual(deletedInstances[0], 'instances/goneMissing');
                    test.strictEqual(deletedInstances[1], 'public_keys/goneMissing');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testGetNicsByTag: {
        testBasic: function(test) {
            var myTag = {
                key: 'foo',
                value: 'bar'
            };
            var passedParams;

            provider.ec2 = {
                describeNetworkInterfaces: function(params) {
                    passedParams = params;
                    return {
                        promise: function() {
                            return q({
                                NetworkInterfaces: [
                                    {
                                        NetworkInterfaceId: '1',
                                        PrivateIpAddress: '1.2.3.4'
                                    },
                                    {
                                        NetworkInterfaceId: '2',
                                        PrivateIpAddress: '2.3.4.5',
                                        Association: {
                                            PublicIp: '3.4.5.6'
                                        }
                                    }
                                ]
                            });
                        }
                    };
                }
            };

            test.expect(7);
            provider.getNicsByTag(myTag)
                .then(function(response) {
                    test.strictEqual(passedParams.Filters[0].Name, 'tag:' + myTag.key);
                    test.strictEqual(response[0].id, '1');
                    test.strictEqual(response[0].ip.private, '1.2.3.4');
                    test.strictEqual(response[0].ip.public, undefined);
                    test.strictEqual(response[1].id, '2');
                    test.strictEqual(response[1].ip.private, '2.3.4.5');
                    test.strictEqual(response[1].ip.public, '3.4.5.6');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testBadTag: function(test) {
            var myTag = 'foo';

            test.expect(1);
            provider.getNicsByTag(myTag)
                .then(function() {
                    test.ok(false, 'getNicsByTag should have thrown');
                })
                .catch(function(err) {
                    test.notStrictEqual(err.message.indexOf('key and value'), -1);
                })
                .finally(function() {
                    test.done();
                });
        },

        testError: function(test) {
            var myTag = {
                key: 'foo',
                value: 'bar'
            };

            provider.ec2 = {
                describeNetworkInterfaces: function() {
                    return {
                        promise: function() {
                            return q.reject(new Error('uh oh'));
                        }
                    };
                }
            };

            test.expect(1);
            provider.getNicsByTag(myTag)
                .then(function() {
                    test.ok(false, 'getNicsByTag should have thrown');
                })
                .catch(function(err) {
                    test.strictEqual(err.message, 'uh oh');
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testGetVmsByTag: {
        testBasic: function(test) {
            var myTag = {
                key: 'foo',
                value: 'bar'
            };
            var passedParams;

            provider.ec2 = {
                describeInstances: function(params) {
                    passedParams = params;
                    return {
                        promise: function() {
                            return q({
                                Reservations: [
                                    {
                                        Instances: [
                                            {
                                                InstanceId: '1',
                                                State: {
                                                    Name: 'running'
                                                },
                                                PrivateIpAddress: '1.2.3.4'
                                            },
                                            {
                                                InstanceId: '2',
                                                State: {
                                                    Name: 'running'
                                                },
                                                PrivateIpAddress: '2.3.4.5',
                                                PublicIpAddress: '3.4.5.6'
                                            }
                                        ]
                                    }
                                ]
                            });
                        }
                    };
                }
            };

            test.expect(6);
            provider.getVmsByTag(myTag)
                .then(function(response) {
                    test.strictEqual(passedParams.Filters[0].Name, 'tag:' + myTag.key);
                    test.strictEqual(response[0].id, '1');
                    test.strictEqual(response[0].ip.private, '1.2.3.4');
                    test.strictEqual(response[1].id, '2');
                    test.strictEqual(response[1].ip.private, '2.3.4.5');
                    test.strictEqual(response[1].ip.public, '3.4.5.6');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testBadTag: function(test) {
            var myTag = 'foo';

            test.expect(1);
            provider.getVmsByTag(myTag)
                .then(function() {
                    test.ok(false, 'getVmsByTag should have thrown');
                })
                .catch(function(err) {
                    test.notStrictEqual(err.message.indexOf('key and value'), -1);
                })
                .finally(function() {
                    test.done();
                });
        },

        testError: function(test) {
            var myTag = {
                key: 'foo',
                value: 'bar'
            };

            provider.ec2 = {
                describeInstances: function() {
                    return {
                        promise: function() {
                            return q.reject(new Error('uh oh'));
                        }
                    };
                }
            };

            test.expect(1);
            provider.getVmsByTag(myTag)
                .then(function() {
                    test.ok(false, 'getVmsByTag should have thrown');
                })
                .catch(function(err) {
                    test.strictEqual(err.message, 'uh oh');
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testElectMaster: function(test) {
        var instances = {
            'id1': {
                privateIp: '1.2.3.4'
            },
            'id2': {
                privateIp: '1.2.4.4'
            }
        };

        provider.launchConfigurationName = 'launchConfig';
        provider.launchConfigMap = {
            'id1': 'launchConfig',
            'id2': 'launchConfig'
        };

        test.expect(1);
        provider.electMaster(instances)
            .then(function(electedMasterId) {
                test.strictEqual(electedMasterId, 'id1');
            })
            .catch(function(err) {
                test.ok(false, err.message);
            })
            .finally(function() {
                test.done();
            });
    },

    testIsValidMaster: {
        setUp: function(callback) {
            instance1 = {
                isMaster: false,
                hostname: 'hostname1',
                mgmtIp: '1.2.3.4',
                privateIp: '1.2.3.4'
            };
            instance2 = {
                isMaster: false,
                hostname: 'hostname2',
                mgmtIp: '5.6.7.8',
                privateIp: '5.6.7.8'
            };

            instances = [instance1, instance2];

            provider.nodeProperties = {
                instanceId: instanceId + 1
            };
            provider.launchConfigurationName = 'launchConfig';
            provider.launchConfigMap = {};
            provider.launchConfigMap[instanceId] = provider.launchConfigurationName;

            provider.s3 = {
                getObject: function() {
                    return {
                        promise: function() {
                            return q({});
                        }
                    };
                }
            };

            callback();
        },

        testIsMaster: function(test) {
            provider.nodeProperties.instanceId = instanceId;

            test.expect(1);
            provider.isValidMaster(instanceId, instances)
                .then(function(isValid) {
                    test.ok(isValid);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testNoInstanceInfo: function(test) {
            provider.s3.getObject = function() {
                return {
                    promise: function() {
                        return q.reject();
                    }
                };
            };

            test.expect(1);
            provider.isValidMaster(instanceId, instances)
                .then(function(isValid) {
                    test.ok(isValid);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testMasterElected: {
        setUp: function(callback) {
            provider.nodeProperties = {
                instanceId: instanceId
            };
            instanceProtectionParams = undefined;

            awsMock = {
                AutoScaling: {
                    setInstanceProtection: function(params, cb) {
                        instanceProtectionParams = params;
                        cb();
                    }
                },
                S3: {
                    listObjectsV2: function() {
                        return {
                            promise: function() {
                                return q(
                                    {
                                        KeyCount: 1,
                                        Contents: []
                                    });
                            }
                        };
                    }
                }
            };

            provider.autoscaling = awsMock.AutoScaling;
            provider.s3 = awsMock.S3;
            provider.providerOptions = {
                s3Bucket: 'foo'
            };

            callback();
        },

        testInstanceProtectionSetWhenMaster: function(test) {
            test.expect(3);
            provider.masterElected(instanceId)
                .then(function() {
                    test.strictEqual(instanceProtectionParams.InstanceIds.length, 1);
                    test.strictEqual(instanceProtectionParams.InstanceIds[0], instanceId);
                    test.ok(instanceProtectionParams.ProtectedFromScaleIn);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testInstanceProtectionNotSetWhenNotMaster: function(test) {
            test.expect(1);
            provider.masterElected('foo')
                .then(function() {
                    test.strictEqual(instanceProtectionParams, undefined);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });

        },

        testOtherMastersSetToNonMaster: function(test) {
            awsMock.S3.listObjectsV2 = function() {
                return {
                    promise: function() {
                        return q(
                            {
                                KeyCount: 1,
                                Contents: [
                                    {
                                        Key: 'instances/5678',
                                        isMaster: true
                                    }
                                ]
                            });
                    }
                };
            };
            awsMock.S3.getObject = function() {
                    return {
                        promise: function() {
                            return q(
                                {
                                    Body: JSON.stringify({
                                        isMaster: true
                                    })
                                });
                        }
                    };
            };

            provider.putInstance = function(instanceId, instance) {
                putInstanceId = instanceId;
                putInstance = instance;
                return q();
            };

            test.expect(2);
            provider.masterElected(instanceId)
                .then(function() {
                    test.strictEqual(putInstanceId, '5678');
                    test.strictEqual(putInstance.isMaster, false);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        }
    }
};
