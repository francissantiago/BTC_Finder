import requests
import logging

def get_balance(address):
    try:
        url = f"https://blockchain.info/q/addressbalance/{address}"
        response = requests.get(url)
        response.raise_for_status()
        balance_satoshis = int(response.text)
        formatted_balance = format(balance_satoshis / 1e8, '.8f')  # Converter satoshis para BTC e formatar com 8 casas decimais
        return formatted_balance
    except Exception as e:
        logging.error(f"Error fetching balance: {str(e)}")
        return None
