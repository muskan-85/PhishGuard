from model.predict import predict_url


TEST_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.wikipedia.org",
    "https://www.google.com/search?q=hello",
    "http://dbs.vote-friend.com/sg?ref=anything",
    "http://paypal-login-security.example.com/verify/account",
    "http://192.168.1.1/login.php?verify=account",
]


for url in TEST_URLS:
    result = predict_url(url)
    print(
        f"{result['result']:10} | "
        f"{result['risk_score']:6.2f}% | "
        f"{url}"
    )
