package config

// Restore the profile from chain_test.go (before 2ed0bb5). The DNS regression
// tests use it to build options without connecting to either local proxy.
const chainTestProfile = `{"outbounds":[
	{"type":"socks","tag":"proxy-a","server":"127.0.0.1","server_port":1080},
	{"type":"socks","tag":"proxy-b","server":"127.0.0.1","server_port":1081}
]}`
