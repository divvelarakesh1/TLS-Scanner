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
│
├── benchmark.py
├── main.py
└── requirements.txt
```


To build
```
make build
```
To run
```
make run
```

