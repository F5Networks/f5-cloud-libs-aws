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

var q;
var fsMock;
var awsMock;
var AwsAutoscaleProvider;
var bigIpMock;
var utilMock;
var provider;

var providerOptions = {
    s3Bucket: 'foo'
};

var user = 'foo';
var password = 'bar';

var iidDoc;

var instance1;
var instance2;

var deletedInstances;

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
            update: function(config) {
                this.configUpdate = config;
            },
        };

        fsMock.reset = function() {
            iidDoc = undefined;
        };

        fsMock.reset();

        utilMock.DEFAULT_RETRY = utilMock.NO_RETRY;
        utilMock.SHORT_RETRY = utilMock.NO_RETRY;

        callback();
    },

    tearDown: function(callback) {
        Object.keys(require.cache).forEach(function(key) {
            delete require.cache[key];
        });
        callback();
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
                        adminPassword: 'myAdminPassword'
                    };
                    instance2 = {
                        isMaster: false,
                        hostname: 'hostname2',
                        mgmtIp: '5.6.7.8',
                        privateIp: '5.6.7.8',
                        mgmtPort: 1000,
                        adminUser: 'myAdminUser',
                        adminPassword: 'myAdminPassword'
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
                describeInstances: function(params, cb) {
                    cb(null, {});
                }
            };

            deletedInstances = [];

            callback();
        },

        testLaunchConfigurationMap: function(test) {
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
            provider.getInstances()
                .then(function(instances) {
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

            provider.ec2.describeInstances = function(params, cb) {
                var data = {
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

                cb(null, data);
            };

            provider.getInstances()
                .then(function(instances) {
                    test.deepEqual(
                       instances.id3,
                       {
                           isMaster: false,
                           hostname: 'missingHostname3',
                           mgmtIp: '7.8.9.0',
                           privateIp: '7.8.9.0'
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

        testDeleteMissingInstances: function(test) {
            const INSTANCES_FOLDER = 'instances/';
            provider.s3.listObjectsV2 = function() {
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
                                    Key: INSTANCES_FOLDER + 'id3'
                                }
                            ]
                        };
                        deferred.resolve(data);
                        return deferred.promise;
                    }
                };
            };

            provider.autoscaling.describeAutoScalingGroups = function(params, cb) {
                var data = {
                    AutoScalingGroups: [
                        {
                            LaunchConfigurationName: 'mainLaunchConfig',
                            Instances: [
                                {
                                    InstanceId: 'id2',
                                    LaunchConfigurationName: 'id2LaunchConfig'
                                }
                            ]
                        }
                    ]
                };

                cb(null, data);
            };

            provider.getInstances()
                .then(function() {
                    test.strictEqual(deletedInstances.length, 2);
                    test.notStrictEqual(deletedInstances.indexOf(INSTANCES_FOLDER + 'id1'), -1);
                    test.notStrictEqual(deletedInstances.indexOf(INSTANCES_FOLDER + 'id3'), -1);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
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

    testPutMasterCredentials: {
        setUp: function(callback) {
            provider.providerOptions = {};
            callback();
        },

        testBasic: function(test) {
            var calledParams;

            provider.s3 = {
                putObject: function(params) {
                    calledParams = params;
                    return {
                        promise: function() {
                            return q();
                        }
                    };
                }
            };

            provider.putMasterCredentials()
                .then(function() {
                    var body = JSON.parse(calledParams.Body);
                    test.strictEqual(body.username, user);
                    test.strictEqual(body.password, password);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testError: function(test) {
            provider.s3 = {
                putObject: function() {
                    return {
                        promise: function() {
                            return q.reject(new Error('uh oh'));
                        }
                    };
                }
            };

            test.expect(1);
            provider.putMasterCredentials()
                .then(function() {
                    test.ok(false, 'should have failed');
                })
                .catch(function(err) {
                    test.notStrictEqual(err.message.indexOf('master credentials'), -1);
                })
                .finally(function() {
                    test.done();
                });
        }
    }
};
