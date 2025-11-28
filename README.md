```
TLS-Scanner/
├── checks/
│   ├── certificates.py
│   ├── protocols.py
│   └── ciphers.py
|   └── attacks.py
|   └── features.py
|   └── vulnerability.py
│
├── core/
│   ├── models.py
│   ├── context.py
│   ├── base_check.py
│   └── scanner.py
│
├── runners/
│   ├── sequential.py
│   └── parallel.py
|
├── targets/
│   ├── targets1.txt
│   └── targets5.txt
|   └── targets10.txt
|   └── targets20.txt
|   └── targets50.txt
|
├── benchmark.py
├── main.py
└── requirements.txt
├── Dockerfile
└── targets.txt
└── Makefile
└── Readme.md
```


To build
```
make build
```
To run
```
make run
```

