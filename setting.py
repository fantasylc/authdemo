SERVER_PORT = 8888
SITE_URL = "http://superliu.me:8888"
WEIBO_OAUTH = {
    'key': '2629645673',
    'secret': '',
}
WEIBO_REDIRECT_URI = SITE_URL + "/auth/weibo/callback/"

OAUTH_ACCESS_TOKEN_URL = "https://api.weibo.com/oauth2/access_token?"
WEIBO_AUTHORIZE_URL = "https://api.weibo.com/oauth2/authorize?"
WEIBO_USER_INFO_URL = "https://api.weibo.com/2/users/show.json"

SECRET_KEY = "*&==q)6tiqqyw%!$twx(03u9!*0+2v!+w9cb=cd_9lvxj8-f&&"

STORE_ID = 16972
STORE_KEY = ''

BANK_PAY_URL = "http://api.cwtong.net/gateway/cwtb/"
CARD_PAY_URL = "http://api.cwtong.net/gateway/cwt/"
PAY_CALLBACK_URL = SITE_URL + "/pay/callback/"
