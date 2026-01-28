import jwt 
from datetime import datetime, timedelta

secret1 = "super_secret_key_for_hmac"

def generate_license(username, days_valid=365, features=None):
    payload = {
        "sub" : username,
        "iat" : int(datetime.utcnow().timestamp()),
        "exp" : int((datetime.utcnow() + timedelta(days=days_valid)).timestamp()),
        "features" : features or []
    }
    token = jwt.encode(payload, secret1, algorithm="HS256")
    return token

if __name__ == "__main__":
    print(generate_license("nishgridtechnology@gmail.com", days_valid=365, features=["pro"])) #chnge email id for giving permissions