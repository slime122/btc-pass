import pytest
from btcseed import gerar_endereco_btc, gerar_endereco_eth

def test_gerar_endereco_btc():
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    endereco = gerar_endereco_btc(mnemonic)
    assert endereco == "1LqBGSKuX6Bp8iTJjG7GtGJEL7bTqY3VYk"

def test_gerar_endereco_eth():
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    endereco = gerar_endereco_eth(mnemonic)
    assert endereco.lower() == "0x8f22aad6f7c2c4a8e1cfc9c5eaef5b9a0b0a3f7f".lower()
