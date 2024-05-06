URL = "http://localhost:8000"

microservices = {
	"app1": {
		"appId": 1,
		"microservice1": {
			"microserviceId": 11,
			"url": "http://localhost:8000/cryptography/encrypt"
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
		"microservice3": {
			"microserviceId": 4,
			"urls": {
				"policy": "http://localhost:8083/zta/policy"
			}
		},
		"microservice4": {
			"microserviceId": 5,
			"urls": {
				"tunnelling": "http://localhost:8084/zta/tunnelling"
			}
		},
		"microservice5": {
			"microserviceId": 6,
			"urls": {
				"orchestration": "http://localhost:8085/zta/orchestration",
				"automation": "http://localhost:8085/zta/automation"
			}
		},
		"microservice6": {
			"microserviceId": 7,
			"urls": {
				"monitoring": "http://localhost:8086/zta/monitoring"
			}
		}
	}
}
