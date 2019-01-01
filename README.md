# Implementation of AES CBC and CTR modes
This is an implementation of the CBC (Cipher Block Chaining) and CTR (Counter) AES modes algorithms in Python, using a supplied random IV, and [PyCrypto](https://github.com/dlitz/pycrypto)'s implementation of AES. It was made for the Week 2 programming assigment of Dan Boneh's Cryptography I [course](https://www.coursera.org/learn/crypto). 

The modes are implemented through four functions:
```python
def cbc_encrypt(message: bytes, key: bytes, IV: bytes) -> bytes:
 ```
```python
def cbc_decrypt(cipher: bytes, key: bytes) -> bytes:
```
```python
def ctr_encrypt(message: bytes, key: bytes, IV: bytes) -> bytes:
```
```python
def ctr_decrypt(cipher: bytes, key: bytes) -> bytes:
```