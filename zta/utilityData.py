microservices = {
	"app1": {
		"appId": 1,
		"microservice1": {
			"microserviceId": 11,
			"urls": {
				"encryption": "http://localhost:8001/cryptography/encrypt"
			}
		},
		"microservice2": {
			"microserviceId": 12,
			"urls": {
				"decryption": "http://localhost:8002/cryptography/decrypt"
			}
		},
		"microservice3": {
			"microserviceId": 13,
			"urls": {
				"logging": "http://localhost:8003/cryptography/logging"
			}
		}
	},
	"app2": {
		"appId": 2,
		"microservice1": {
			"microserviceId": 21,
			"urls": {
				"apikey_generation": "http://localhost:8010/auth-generator/generate/api-key",
				"oauth2_generation": "http://localhost:8010/auth-generator/generate/oauth2",
				"jwt_generation": "http://localhost:8010/auth-generator/generate/jwt"
			}
		},
		"microservice2": {
			"microserviceId": 22,
			"urls": {
				"apikey_verification": "http://localhost:8011/auth-generator/verify/api-key",
				"oauth2_verification": "http://localhost:8011/auth-generator/verify/oauth2",
				"jwt_verification": "http://localhost:8011/auth-generator/verify/jwt"
			}
		},
		"microservice3": {
			"microserviceId": 23,
			"urls": {
				"getting_info": "http://localhost:8012/auth-generator/data-info",
				"saving_info": "http://localhost:8012/auth-generator/data-new"
			}
		},
		"microservice4": {
			"microserviceId": 24,
			"urls": {
				"logging": "http://localhost:8013/auth-generator/logging"
			}
		}
	},
	"app3": {
		"appId": 3,
		"microservice1": {
			"microserviceId": 31,
			"urls": {
				"verification": "http://localhost:8020/digital-signature/verify"
			}
		},
		"microservice2": {
			"microserviceId": 32,
			"urls": {
				"access_control": "http://localhost:8021/digital-signature/access-control"
			}
		},
		"microservice3": {
			"microserviceId": 33,
			"urls": {
				"logging": "http://localhost:8022/digital-signature/logging"
			}
		}
	},
	"app4": {
		"appId": 4,
		"microservice1": {
			"microserviceId": 41,
			"urls": {
				"hashing": "http://localhost:8030/hashing/hash"
			}
		},
		"microservice2": {
			"microserviceId": 42,
			"urls": {
				"verification": "http://localhost:8031/hashing/verify"
			}
		},
		"microservice3": {
			"microserviceId": 43,
			"urls": {
				"reporting": "http://localhost:8032/hashing/reporting"
			}
		},
		"microservice4": {
			"microserviceId": 44,
			"urls": {
				"policy": "http://localhost:8033/hashing/policy"
			}
		},
		"microservice5": {
			"microserviceId": 45,
			"urls": {
				"logging": "http://localhost:8034/hashing/logging"
			}
		}
	},
	"app5": {
		"appId": 5,
		"microservice1": {
			"microserviceId": 51,
			"urls": {
				"storage": "http://localhost:8040/password/store",
				"retrieval": "http://localhost:8040/password/retrieve",
				"update": "http://localhost:8040/password/update"
			}
		},
		"microservice2": {
			"microserviceId": 52,
			"urls": {
				"verification": "http://localhost:8041/password/verify"
			}
		},
		"microservice3": {
			"microserviceId": 53,
			"urls": {
				"reset": "http://localhost:8042/password/reset"
			}
		},
		"microservice4": {
			"microserviceId": 54,
			"urls": {
				"policy": "http://localhost:8043/password/policy"
			}
		},
		"microservice5": {
			"microserviceId": 55,
			"urls": {
				"logging": "http://localhost:8044/password/logging"
			}
		}
	},
	"app6": {
		"appId": 6,
		"microservice1": {
			"microserviceId": 61,
			"urls": {
				"store": "http://localhost:8050/file/store",
				"retrieve": "http://localhost:8050/file/retrieve"
			}
		},
		"microservice2": {
			"microserviceId": 62,
			"urls": {
				"storage": "http://localhost:8051/file/storage",
				"retrieval": "http://localhost:8051/file/retrieval"
			}
		},
		"microservice3": {
			"microserviceId": 63,
			"urls": {
				"encryption": "http://localhost:8052/file/encrypt",
				"decryption": "http://localhost:8052/file/decrypt"
			}
		},
		"microservice4": {
			"microserviceId": 64,
			"urls": {
				"access_control": "http://localhost:8053/file/access-control"
			}
		},
		"microservice5": {
			"microserviceId": 65,
			"urls": {
				"logging": "http://localhost:8054/file/logging"
			}
		}
	},
	"app7": {
		"appId": 7,
		"microservice1": {
			"microserviceId": 71,
			"urls": {
				"masking": "http://localhost:8060/data/mask",
				"unmasking": "http://localhost:8060/data/unmask"
			}
		},
		"microservice2": {
			"microserviceId": 72,
			"urls": {
				"storage": "http://localhost:8061/data/store",
				"retrieval": "http://localhost:8061/data/retrieve"
			}
		},
		"microservice3": {
			"microserviceId": 73,
			"urls": {
				"access_control": "http://localhost:8062/data/access-control"
			}
		},
		"microservice4": {
			"microserviceId": 74,
			"urls": {
				"logging": "http://localhost:8063/data/logging"
			}
		}
	},
	"app8": {
		"appId": 8,
		"microservice1": {
			"microserviceId": 81,
			"urls": {
				"reporting": "http://localhost:8080/intelligence/report"
			}
		},
		"microservice2": {
			"microserviceId": 82,
			"urls": {
				"retrieval": "http://localhost:8081/intelligence/retrieve"
			}
		},
		"microservice3": {
			"microserviceId": 83,
			"urls": {
				"incident": "http://localhost:8082/intelligence/incident",
				"threats": "http://localhost:8082/intelligence/threats"
			}
		},
		"microservice4": {
			"microserviceId": 84,
			"urls": {
				"analysis": "http://localhost:8083/intelligence/analysis"
			}
		},
		"microservice5": {
			"microserviceId": 85,
			"urls": {
				"logging": "http://localhost:8084/intelligence/logging"
			}
		}
	},
	"zta": {
		"appId": 9,
		"microservice1": {
			"microserviceId": 1,
			"urls": {
				"governance": "http://localhost:8080/zta/governance"
			}
		},
		"microservice2": {
			"microserviceId": 2,
			"urls": {
				"iam": "http://localhost:8081/zta/iam"
			}
		},
		"microservice3": {
			"microserviceId": 3,
			"urls": {
				"network": "http://localhost:8082/zta/network"
			}
		},
		"microservice4": {
			"microserviceId": 4,
			"urls": {
				"acl": "http://localhost:8083/zta/acl"
			}
		},
		"microservice5": {
			"microserviceId": 5,
			"urls": {
				"tunnelling": "http://localhost:8085/zta/tunnelling"
			}
		},
		"microservice6": {
			"microserviceId": 6,
			"urls": {
				"encryption": "http://localhost:8086/zta/encrypt",
				"decryption": "http://localhost:8086/zta/decrypt",
				"hashing": "http://localhost:8086/zta/hash"
			}
		},
		"microservice7": {
			"microserviceId": 7,
			"urls": {
				"monitoring": "http://localhost:8087/zta/monitoring"
			}
		}
	}
}
